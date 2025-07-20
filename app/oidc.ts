// Simple OIDC implementation without external library dependencies

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

// Get access token
export const getAccessToken = (): string | null => {
  if (typeof window !== 'undefined') {
    return sessionStorage.getItem('oidc_access_token');
  }
  return null;
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
    scope: process.env.NEXT_PUBLIC_OIDC_SCOPE || "openid",
  };
};

// Generate random state
const generateState = () => {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
};

// Generate authorization URL
export const generateAuthUrl = async (): Promise<string> => {
  const { endpoint, clientId } = getOIDCConfig();
  
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
      scope: 'openid profile offline_access',
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

// Handle OIDC callback and exchange code for token
export const handleOIDCCallback = async (code: string, state: string): Promise<string> => {
  const { endpoint, clientId, scope } = getOIDCConfig();
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
      scope: scope
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
    
    // Store the access token
    storeAccessToken(tokenSet.access_token);
    
    // Clear PKCE state
    clearPKCEState();
    
    return tokenSet.access_token;
  } catch (error) {
    console.error('Error handling OIDC callback:', error);
    throw new Error('Failed to exchange code for token');
  }
};

// Logout function
export const logout = () => {
  clearAccessToken();
  clearPKCEState();
}; 