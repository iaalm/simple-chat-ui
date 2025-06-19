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

Create a `.env.local` file in the root directory and add your custom values:

```bash
NEXT_PUBLIC_TITLE="My Custom Chat Bot"
NEXT_PUBLIC_DESCRIPTION="A custom description for my chat bot"
NEXT_PUBLIC_API_BASE="https://localhost:5000"
NEXT_PUBLIC_EXTRA_PARAMETERS="Max Tokens:max_tokens=100;Temperature:temperature=0.7"
```

### URL Parameters

You can configure the chat interface using URL parameters:

- `key`: Set your API key directly in the URL (e.g., `?key=your-api-key`)
- `model`: Pre-select a specific model (e.g., `?model=model-name`)

Example URL with parameters:
```
http://localhost:3000?key=your-api-key&model=model-name
```

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

