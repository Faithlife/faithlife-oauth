declare module 'faithlife-oauth' {
  function createConsumer(options?: { rootUrl?: string, token?: string, secret?: string }): Consumer;
  interface Consumer {
    generateAuthHeader(options?: {
      oauth_callback?: string,
      oauth_token?: string,
      oauth_token_secret?: string,
      oauth_verifier?: string,
      signatureMethod?: string,
    }): string;
  }
}