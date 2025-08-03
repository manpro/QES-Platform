/**
 * QES Platform JavaScript/TypeScript SDK
 * 
 * A comprehensive SDK for integrating with the QES Platform API,
 * providing qualified electronic signature services compliant with
 * eIDAS regulation and ETSI standards.
 * 
 * @example
 * ```typescript
 * import { QESClient } from '@qes-platform/sdk';
 * 
 * const client = new QESClient({
 *   apiUrl: 'https://api.qes-platform.com/v1',
 *   apiKey: 'your-api-key',
 *   tenantId: 'your-tenant-id'
 * });
 * 
 * // Authenticate user
 * const authResult = await client.auth.login({
 *   provider: 'freja-se',
 *   userIdentifier: 'user@example.com'
 * });
 * 
 * // Sign document
 * const signResult = await client.signatures.sign({
 *   document: documentBuffer,
 *   documentName: 'contract.pdf',
 *   signatureFormat: 'PAdES-LTA'
 * });
 * ```
 */

export { QESClient } from './client';
export * from './types';
export * from './errors';
export * from './managers';

// Version information
export const VERSION = '1.0.0';
export const API_VERSION = 'v1';