# Simple chat UI


## Getting Started
This project is a minimalist chatbot interface designed for OpenAI-compatible chat APIs.
Run the following commands to build the user interface, then serve the "out" folder using an HTTP server. You can integrate it into any backend framework such as Flask, Django, or any other framework of your choice.

```bash
npm install
npm run build
```

### Environment Variables

You can customize the chat bot's appearance by setting the following environment variables:

- `NEXT_PUBLIC_TITLE`: The title of the chat bot (defaults to "Chat bot")
- `NEXT_PUBLIC_DESCRIPTION`: The description of the chat bot (defaults to "The chat bot")
- `NEXT_PUBLIC_API_BASE`: The base URL for your API (e.g., "https://localhost:5000")
- `NEXT_PUBLIC_EXTRA_PARAMETERS`: Additional parameters to send with requests (format: "Display Name:param_name=value;Display Name2:param_name2=value2")
- `NEXT_PUBLIC_STREAM`: Enable streaming responses (set to "true" to enable)
- `NEXT_PUBLIC_OIDC_ENDPOINT`: OIDC provider endpoint (e.g., "https://your-oidc-provider.com/.well-known/openid_configuration")
- `NEXT_PUBLIC_OIDC_CLIENT_ID`: OIDC client ID for authentication
- `NEXT_PUBLIC_OIDC_SCOPE`: OIDC scope for authentication

Create a `.env.local` file in the root directory and add your custom values:

```bash
NEXT_PUBLIC_TITLE="My Custom Chat Bot"
NEXT_PUBLIC_DESCRIPTION="A custom description for my chat bot"
NEXT_PUBLIC_API_BASE="https://localhost:5000"
NEXT_PUBLIC_EXTRA_PARAMETERS="Max Tokens:max_tokens=100;Temperature:temperature=0.7"
NEXT_PUBLIC_STREAM="true"
NEXT_PUBLIC_OIDC_ENDPOINT="https://your-oidc-provider.com/.well-known/openid_configuration"
NEXT_PUBLIC_OIDC_CLIENT_ID="your-client-id"
```

### URL Parameters

You can configure the chat interface using URL parameters:

- `key`: Set your API key directly in the URL (e.g., `?key=your-api-key`)
- `model`: Pre-select a specific model (e.g., `?model=model-name`)

Example URL with parameters:
```
http://localhost:3000?key=your-api-key&model=model-name
```

### OIDC Authentication

When `NEXT_PUBLIC_OIDC_ENDPOINT` and `NEXT_PUBLIC_OIDC_CLIENT_ID` are configured, the chat interface will use OIDC authentication instead of API key input. The authentication flow uses Authorization Code Flow with PKCE for security.

**Features:**
- Automatic token management
- Secure PKCE authentication flow
- Built-in OIDC implementation (no external dependencies)
- Fallback to API key if OIDC is not configured

**Setup:**
1. Configure your OIDC provider (e.g., Auth0, Keycloak, etc.)
2. Set the redirect URI to `http://localhost:3000` (for development)
3. Add the environment variables to your `.env.local` file
4. The login/logout buttons will appear in the header

**Note:** This implementation uses a simplified PKCE flow. For production use with strict security requirements, consider using a dedicated OIDC library.

# Dev

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.


This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

