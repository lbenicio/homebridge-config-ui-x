import { createHash, randomBytes } from 'node:crypto'

import {
  BadGatewayException,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common'
import { createRemoteJWKSet, jwtVerify } from 'jose'

import { API_PREFIX } from '../api.constants.js'
import { ConfigService } from '../config/config.service.js'
import { Logger } from '../logger/logger.service.js'

type JWTPayload = import('jose').JWTPayload

interface OidcDiscoveryDocument {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
  userinfo_endpoint?: string
}

interface OidcTokenResponse {
  access_token?: string
  id_token?: string
}

export interface OidcIdentity {
  issuer: string
  subject: string
  email?: string
  groups: string[]
}

export interface OidcLoginResult {
  identity: OidcIdentity
  returnTo: string
}

interface PendingAuthorization {
  codeVerifier: string
  nonce: string
  redirectUri: string
  returnTo: string
  expiresAt: number
}

interface OidcFetchInit {
  method?: string
  headers?: Record<string, string>
  body?: URLSearchParams
}

const AUTHORIZATION_TTL_MS = 10 * 60 * 1000
const DISCOVERY_TTL_MS = 5 * 60 * 1000
const REQUEST_TIMEOUT_MS = 10 * 1000

@Injectable()
export class OidcService {
  private pendingAuthorizations = new Map<string, PendingAuthorization>()
  private discovery?: { document: OidcDiscoveryDocument, expiresAt: number }
  private jwks?: ReturnType<typeof createRemoteJWKSet>

  constructor(
    private readonly configService: ConfigService,
    private readonly logger: Logger,
  ) {}

  get enabled() {
    return this.configService.oidc.enabled
  }

  get loginUrl() {
    return `${API_PREFIX}/auth/oidc/login`
  }

  async createAuthorizationUrl(returnTo: string, redirectUri: string): Promise<string> {
    this.requireEnabled()
    const discovery = await this.getDiscovery()
    const state = this.randomToken()
    const nonce = this.randomToken()
    const codeVerifier = this.randomToken(48)
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    this.removeExpiredAuthorizations()
    this.pendingAuthorizations.set(state, {
      codeVerifier,
      nonce,
      redirectUri,
      returnTo: this.safeReturnTo(returnTo),
      expiresAt: Date.now() + AUTHORIZATION_TTL_MS,
    })

    const authorizationUrl = new URL(discovery.authorization_endpoint)
    authorizationUrl.searchParams.set('client_id', this.configService.oidc.clientId)
    authorizationUrl.searchParams.set('redirect_uri', redirectUri)
    authorizationUrl.searchParams.set('response_type', 'code')
    authorizationUrl.searchParams.set('scope', this.configService.oidc.scopes)
    authorizationUrl.searchParams.set('state', state)
    authorizationUrl.searchParams.set('nonce', nonce)
    authorizationUrl.searchParams.set('code_challenge', codeChallenge)
    authorizationUrl.searchParams.set('code_challenge_method', 'S256')
    return authorizationUrl.toString()
  }

  async completeAuthorization(code: string, state: string): Promise<OidcLoginResult> {
    this.requireEnabled()
    const pending = this.takeAuthorization(state)
    const discovery = await this.getDiscovery()
    const tokenResponse = await this.exchangeCode(discovery, code, pending)
    const identity = await this.readIdentity(discovery, tokenResponse, pending.nonce)
    this.checkAllowList(identity)

    return {
      identity,
      returnTo: pending.returnTo,
    }
  }

  private requireEnabled() {
    const config = this.configService.oidc
    if (!config.enabled || !config.issuer || !config.clientId || !config.clientSecret) {
      throw new BadGatewayException('OIDC is enabled but not fully configured.')
    }
    let issuer: URL
    try {
      issuer = new URL(config.issuer)
    } catch {
      throw new BadGatewayException('OIDC issuer is not a valid URL.')
    }
    if (issuer.protocol !== 'https:') {
      throw new BadGatewayException('OIDC issuer must use HTTPS.')
    }
  }

  private async getDiscovery(): Promise<OidcDiscoveryDocument> {
    if (this.discovery && this.discovery.expiresAt > Date.now()) {
      return this.discovery.document
    }

    const issuer = this.configService.oidc.issuer.replace(/\/+$/, '')
    const discoveryUrl = `${issuer}/.well-known/openid-configuration`
    const document = await this.fetchJson<OidcDiscoveryDocument>(discoveryUrl)
    if (!document.issuer || !document.authorization_endpoint || !document.token_endpoint || !document.jwks_uri) {
      throw new BadGatewayException('OIDC discovery response is incomplete.')
    }
    if (this.normalizeIssuer(document.issuer) !== this.normalizeIssuer(this.configService.oidc.issuer)) {
      throw new BadGatewayException('OIDC discovery issuer does not match the configured issuer.')
    }

    this.discovery = {
      document,
      expiresAt: Date.now() + DISCOVERY_TTL_MS,
    }
    this.jwks = undefined
    return document
  }

  private async exchangeCode(
    discovery: OidcDiscoveryDocument,
    code: string,
    pending: PendingAuthorization,
  ): Promise<OidcTokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: pending.redirectUri,
      client_id: this.configService.oidc.clientId,
      client_secret: this.configService.oidc.clientSecret,
      code_verifier: pending.codeVerifier,
    })
    const response = await this.fetchJson<OidcTokenResponse>(discovery.token_endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        'accept': 'application/json',
      },
      body,
    })
    if (!response.access_token) {
      throw new BadGatewayException('OIDC token response did not contain an access token.')
    }
    return response
  }

  private async readIdentity(
    discovery: OidcDiscoveryDocument,
    tokenResponse: OidcTokenResponse,
    nonce: string,
  ): Promise<OidcIdentity> {
    if (tokenResponse.id_token) {
      try {
        const verified = await jwtVerify(tokenResponse.id_token, await this.getJwks(discovery), {
          issuer: discovery.issuer,
          audience: this.configService.oidc.clientId,
          clockTolerance: 5,
        })
        if (verified.payload.nonce !== nonce) {
          throw new UnauthorizedException('OIDC nonce validation failed.')
        }
        return this.identityFromClaims(discovery.issuer, verified.payload)
      } catch (error) {
        this.logger.warn(`OIDC ID token verification failed: ${error instanceof Error ? error.message : 'unknown error'}.`)
        throw new UnauthorizedException('OIDC identity verification failed.')
      }
    }

    if (!discovery.userinfo_endpoint) {
      throw new BadGatewayException('OIDC token response did not contain an ID token.')
    }
    const userinfo = await this.fetchJson<Record<string, unknown>>(discovery.userinfo_endpoint, {
      headers: {
        authorization: `Bearer ${tokenResponse.access_token}`,
        accept: 'application/json',
      },
    })
    return this.identityFromClaims(discovery.issuer, userinfo)
  }

  private async getJwks(discovery: OidcDiscoveryDocument) {
    if (!this.jwks) {
      this.jwks = createRemoteJWKSet(new URL(discovery.jwks_uri))
    }
    return this.jwks
  }

  private identityFromClaims(issuer: string, claims: JWTPayload | Record<string, unknown>): OidcIdentity {
    const subject = claims.sub
    if (typeof subject !== 'string' || !subject) {
      throw new UnauthorizedException('OIDC identity did not contain a subject.')
    }

    const email = typeof claims.email === 'string' ? claims.email.trim().toLowerCase() : undefined
    const groupsValue = claims.groups
    const groups = Array.isArray(groupsValue)
      ? groupsValue.filter((group): group is string => typeof group === 'string').map(group => group.toLowerCase())
      : typeof groupsValue === 'string'
        ? groupsValue.split(/[ ,]+/).map(group => group.toLowerCase()).filter(Boolean)
        : []

    return { issuer, subject, email, groups }
  }

  private checkAllowList(identity: OidcIdentity) {
    const { allowedEmails, allowedGroups } = this.configService.oidc
    if (allowedEmails.length && (!identity.email || !allowedEmails.includes(identity.email))) {
      throw new ForbiddenException('This OIDC account is not allowed to access Homebridge.')
    }
    if (allowedGroups.length && !allowedGroups.some(group => identity.groups.includes(group))) {
      throw new ForbiddenException('This OIDC account is not in an allowed OIDC group.')
    }
  }

  private takeAuthorization(state: string): PendingAuthorization {
    const pending = this.pendingAuthorizations.get(state)
    this.pendingAuthorizations.delete(state)
    if (!pending || pending.expiresAt <= Date.now()) {
      throw new UnauthorizedException('OIDC authorization has expired or is invalid.')
    }
    return pending
  }

  private removeExpiredAuthorizations() {
    const now = Date.now()
    for (const [state, pending] of this.pendingAuthorizations) {
      if (pending.expiresAt <= now) {
        this.pendingAuthorizations.delete(state)
      }
    }
  }

  private safeReturnTo(value: string): string {
    if (!/^\/(?![\\/])/.test(value)) {
      return '/'
    }
    try {
      const parsed = new URL(value, 'https://homebridge.invalid')
      return `${parsed.pathname}${parsed.search}${parsed.hash}`
    } catch {
      return '/'
    }
  }

  private randomToken(bytes = 32) {
    return randomBytes(bytes).toString('base64url')
  }

  private normalizeIssuer(value: string) {
    return value.replace(/\/+$/, '')
  }

  private async fetchJson<T>(url: string, init?: OidcFetchInit): Promise<T> {
    let response: Response
    try {
      response = await fetch(url, {
        ...init,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      })
    } catch {
      throw new BadGatewayException('Unable to reach the OIDC provider.')
    }

    let body: unknown
    try {
      body = await response.json()
    } catch {
      throw new BadGatewayException('OIDC provider returned an invalid response.')
    }
    if (!response.ok) {
      throw new BadGatewayException(`OIDC provider returned HTTP ${response.status}.`)
    }
    return body as T
  }
}
