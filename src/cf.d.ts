declare module "cloudflare:workers" {
  export class DurableObject<E = unknown> { constructor(ctx: any, env: E); protected ctx: any; protected env: E }
}
