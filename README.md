This is a [Next.js](https://nextjs.org) project bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

## Getting Started

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

## Environment Variables

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

## URL Parameters

You can configure the chat interface using URL parameters:

- `key`: Set your API key directly in the URL (e.g., `?key=your-api-key`)
- `model`: Pre-select a specific model (e.g., `?model=model-name`)

Example URL with parameters:
```
http://localhost:3000?key=your-api-key&model=model-name
```

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
