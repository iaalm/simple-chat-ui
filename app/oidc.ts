// Simple OIDC implementation without external library dependencies
// 
// This implementation now includes automatic token refresh functionality:
// 
// 1. getAccessToken() - Async function that automatically checks token expiration
//    and attempts to refresh if needed. Returns null and redirects to login if refresh fails.
// 
// 2. getAccessTokenSync() - Synchronous version for UI rendering (backward compatibility)
// 
// 3. isAuthenticated() - Synchronous check for UI state
// 
// 4. isAuthenticatedAsync() - Async check with automatic refresh
// 
// 5. refreshAccessToken() - Manual refresh function
// 
// Usage:
// - For API calls: await getAccessToken() - handles refresh automatically
// - For UI rendering: getAccessTokenSync() or isAuthenticated()
// - For authentication checks: isAuthenticatedAsync() - handles refresh automatically
//
// The system automatically stores refresh tokens and expiration times when tokens are received,
// and will attempt to refresh expired tokens before redirecting to login.

// Generate PKCE code verifier and challenge
export const generatePKCE = async () => {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const codeVerifier = btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  
  // Generate SHA256 hash of code verifier
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  
  // Convert hash to base64url
  const hashArray = new Uint8Array(hashBuffer);
  const codeChallenge = btoa(String.fromCharCode(...hashArray))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  
  return { codeVerifier, codeChallenge };
};

// Store PKCE state in session storage
export const storePKCEState = (state: string, codeVerifier: string) => {
  if (typeof window !== 'undefined') {
    sessionStorage.setItem('oidc_state', state);
    sessionStorage.setItem('oidc_code_verifier', codeVerifier);
  }
};

// Retrieve PKCE state from session storage
export const getPKCEState = () => {
  if (typeof window !== 'undefined') {
    const state = sessionStorage.getItem('oidc_state');
    const codeVerifier = sessionStorage.getItem('oidc_code_verifier');
    return { state, codeVerifier };
  }
  return { state: null, codeVerifier: null };
};

// Clear PKCE state from session storage
export const clearPKCEState = () => {
  if (typeof window !== 'undefined') {
    sessionStorage.removeItem('oidc_state');
    sessionStorage.removeItem('oidc_code_verifier');
  }
};

// Store access token
export const storeAccessToken = (token: string) => {
  if (typeof window !== 'undefined') {
    sessionStorage.setItem('oidc_access_token', token);
  }
};

// Store complete token set (access token, refresh token, expiration)
export const storeTokenSet = (tokenSet: { access_token: string; refresh_token?: string; expires_in?: number }) => {
  if (typeof window !== 'undefined') {
    sessionStorage.setItem('oidc_access_token', tokenSet.access_token);
    if (tokenSet.refresh_token) {
      sessionStorage.setItem('oidc_refresh_token', tokenSet.refresh_token);
    }
    if (tokenSet.expires_in) {
      const expiresAt = Date.now() + (tokenSet.expires_in * 1000);
      sessionStorage.setItem('oidc_expires_at', expiresAt.toString());
    }
  }
};

// Get refresh token
export const getRefreshToken = (): string | null => {
  if (typeof window !== 'undefined') {
    return sessionStorage.getItem('oidc_refresh_token');
  }
  return null;
};

// Get token expiration time
export const getTokenExpiration = (): number | null => {
  if (typeof window !== 'undefined') {
    const expiresAt = sessionStorage.getItem('oidc_expires_at');
    return expiresAt ? parseInt(expiresAt, 10) : null;
  }
  return null;
};

// Clear refresh token
export const clearRefreshToken = () => {
  if (typeof window !== 'undefined') {
    sessionStorage.removeItem('oidc_refresh_token');
    sessionStorage.removeItem('oidc_expires_at');
  }
};

// Decode JWT token (without verification)
export const decodeJWT = (token: string): { exp?: number; [key: string]: unknown } | null => {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
  } catch (error) {
    console.error('Error decoding JWT:', error);
    return null;
  }
};

// Check if token is expired
export const isTokenExpired = (token: string): boolean => {
  const decoded = decodeJWT(token);
  if (!decoded || !decoded.exp) {
    return true;
  }
  
  // Add 30 second buffer to prevent edge cases
  const currentTime = Math.floor(Date.now() / 1000) + 30;
  return decoded.exp < currentTime;
};

// Refresh access token using refresh token
export const refreshAccessToken = async (): Promise<string | null> => {
  const refreshToken = getRefreshToken();
  if (!refreshToken) {
    return null;
  }

  const { endpoint, clientId, scope } = getOIDCConfig();
  
  try {
    // Discover OIDC configuration
    const response = await fetch(endpoint);
    if (!response.ok) {
      throw new Error(`Failed to fetch OIDC configuration: ${response.status}`);
    }
    
    const config = await response.json();
    
    // Exchange refresh token for new access token
    const tokenParams = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      // some auth provider use audience while some use scope, so we need to add both
      scope: scope,
      audience: scope,
    });
    
    // Add client_id only if provided
    if (clientId) {
      tokenParams.append('client_id', clientId);
    }
    
    const tokenResponse = await fetch(config.token_endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: tokenParams,
    });
    
    if (!tokenResponse.ok) {
      const errorData = await tokenResponse.json().catch(() => ({}));
      throw new Error(`Token refresh failed: ${errorData.error || tokenResponse.status}`);
    }
    
    const tokenSet = await tokenResponse.json();
    
    if (!tokenSet.access_token) {
      throw new Error('No access token received from refresh');
    }
    
    // Store the new token set
    storeTokenSet(tokenSet);
    
    return tokenSet.access_token;
  } catch (error) {
    console.error('Error refreshing access token:', error);
    // Clear tokens on refresh failure
    clearSessionStorage();
    return null;
  }
};

// Get access token with automatic refresh
export const getAccessToken = async (): Promise<string | null> => {
  if (typeof window !== 'undefined') {
    const token = sessionStorage.getItem('oidc_access_token');
    
    if (!token) {
      return null;
    }
    
    // Check if token is expired
    if (isTokenExpired(token)) {
      console.log('Access token expired, attempting refresh...');
      
      // Try to refresh the token
      const newToken = await refreshAccessToken();
      
      if (newToken) {
        return newToken;
      } else {
        // Refresh failed, redirect to login
        console.log('Token refresh failed, redirecting to login...');
        await redirectToLogin();
        return null;
      }
    }
    
    return token;
  }
  return null;
};

// Get access token (synchronous version for backward compatibility)
export const getAccessTokenSync = (): string | null => {
  if (typeof window !== 'undefined') {
    return sessionStorage.getItem('oidc_access_token');
  }
  return null;
};

// Check if user is authenticated (synchronous check)
export const isAuthenticated = (): boolean => {
  const token = getAccessTokenSync();
  if (!token) {
    return false;
  }
  
  // Check if token is expired
  return !isTokenExpired(token);
};

// Check if user is authenticated (async version with refresh)
export const isAuthenticatedAsync = async (): Promise<boolean> => {
  const token = await getAccessToken();
  return !!token;
};

// Clear access token
export const clearAccessToken = () => {
  if (typeof window !== 'undefined') {
    sessionStorage.removeItem('oidc_access_token');
  }
};

// Check if OIDC is configured
export const isOIDCConfigured = (): boolean => {
  return !!process.env.NEXT_PUBLIC_OIDC_ENDPOINT;
};

// Get OIDC configuration
export const getOIDCConfig = () => {
  return {
    endpoint: process.env.NEXT_PUBLIC_OIDC_ENDPOINT!,
    clientId: process.env.NEXT_PUBLIC_OIDC_CLIENT_ID || undefined,
    scope: process.env.NEXT_PUBLIC_OIDC_SCOPE || "openid offline_access profile",
    audience: process.env.NEXT_PUBLIC_OIDC_AUDIENCE || process.env.NEXT_PUBLIC_OIDC_SCOPE || "openid offline_access profile",
  };
};

// Generate random state
const generateState = () => {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
};

// Generate authorization URL
const generateAuthUrl = async (): Promise<string> => {
  const { endpoint, clientId, scope, audience } = getOIDCConfig();
  
  try {
    // Discover OIDC configuration
    const response = await fetch(endpoint);
    if (!response.ok) {
      throw new Error(`Failed to fetch OIDC configuration: ${response.status}`);
    }
    
    const config = await response.json();
    const { codeVerifier, codeChallenge } = await generatePKCE();
    const state = generateState();
    
    // Store state and code verifier for later verification
    storePKCEState(state, codeVerifier);
    
    // Build authorization URL
    const params = new URLSearchParams({
      response_type: 'code',
      // some auth provider use audience while some use scope, so we need to add both
      scope: scope,
      audience: audience,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
      redirect_uri: window.location.origin + window.location.pathname,
    });
    
    // Add client_id only if provided
    if (clientId) {
      params.append('client_id', clientId);
    }
    
    return `${config.authorization_endpoint}?${params.toString()}`;
  } catch (error) {
    console.error('Error generating auth URL:', error);
    throw new Error('Failed to generate authorization URL');
  }
};

export const redirectToLogin = async () => {
  setAuthenticating(true);
  const authUrl = await generateAuthUrl();
  window.location.href = authUrl;
};

// Handle OIDC callback and exchange code for token
export const handleOIDCCallback = async (code: string, state: string): Promise<string> => {
  const { endpoint, clientId, scope, audience } = getOIDCConfig();
  const { state: storedState, codeVerifier } = getPKCEState();
  
  if (!storedState || !codeVerifier) {
    throw new Error('No PKCE state found');
  }
  
  if (state !== storedState) {
    throw new Error('State mismatch');
  }
  
  try {
    // Discover OIDC configuration
    const response = await fetch(endpoint);
    if (!response.ok) {
      throw new Error(`Failed to fetch OIDC configuration: ${response.status}`);
    }
    
    const config = await response.json();
    
    // Exchange code for token
    const tokenParams = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      code_verifier: codeVerifier,
      redirect_uri: window.location.origin + window.location.pathname,
      // some auth provider use audience while some use scope, so we need to add both
      scope: scope,
      audience: audience,
    });
    
    // Add client_id only if provided
    if (clientId) {
      tokenParams.append('client_id', clientId);
    }
    
    const tokenResponse = await fetch(config.token_endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: tokenParams,
    });
    
    if (!tokenResponse.ok) {
      const errorData = await tokenResponse.json().catch(() => ({}));
      throw new Error(`Token exchange failed: ${errorData.error || tokenResponse.status}`);
    }
    
    const tokenSet = await tokenResponse.json();
    
    if (!tokenSet.access_token) {
      throw new Error('No access token received');
    }
    
    // Store the complete token set (access token, refresh token, expiration)
    storeTokenSet(tokenSet);
    
    // Clear PKCE state
    clearPKCEState();

    setAuthenticating(false);
    
    return tokenSet.access_token;
  } catch (error) {
    console.error('Error handling OIDC callback:', error);
    throw new Error('Failed to exchange code for token');
  }
};

export const oidcLogout = async () => {
  const { endpoint, clientId } = getOIDCConfig();
  try {
    // Discover OIDC configuration
    const response = await fetch(endpoint);
    if (!response.ok) {
      throw new Error(`Failed to fetch OIDC configuration: ${response.status}`);
    }
    
    const config = await response.json();

    
    const logout_params = new URLSearchParams({
      returnTo: window.location.origin + window.location.pathname,
    });
    if (clientId) {
      logout_params.append('client_id', clientId);
    }

    const logout_url = config.end_session_endpoint;
    if (logout_url) {
      window.location.href = logout_url + "?" + logout_params.toString();
    }
    else {
      console.warn("Auth provider does not support logout endpoint");
    }
  } catch (error) {
    console.error('Error fetching OIDC configuration:', error);
  }
}

// Logout function
export const clearSessionStorage = () => {
  clearAccessToken();
  clearPKCEState();
  clearRefreshToken();
};

export const setAuthenticating = (isAuthenticating: boolean) => {
  if (typeof window !== 'undefined') {
    sessionStorage.setItem('oidc_authenticating', isAuthenticating.toString());
  }
};

export const getAuthenticating = (): boolean => {
  if (typeof window !== 'undefined') {
    return sessionStorage.getItem('oidc_authenticating') === 'true';
  }
  return false;
};