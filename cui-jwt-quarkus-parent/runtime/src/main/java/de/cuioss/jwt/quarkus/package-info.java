/**
 * <h2>CUI JWT Quarkus Extension</h2>
 * <p>
 * This package provides Quarkus integration for the CUI JWT validation library.
 * It enables Quarkus applications to easily configure and use JWT validation
 * with proper CDI integration, metrics, and health checks.
 * </p>
 * <p>
 * The extension provides:
 * </p>
 * <ul>
 * <li>Configuration properties for JWT validation</li>
 * <li>CDI producers for token validators</li>
 * <li>Integration with Quarkus security</li>
 * <li>Metrics for token validation events</li>
 * <li>Health checks for JWT validation</li>
 * </ul>
 * <p>
 * This extension follows the Quarkus extension architecture with separate
 * runtime and deployment modules.
 * </p>
 * 
 * @since 1.0
 */
package de.cuioss.jwt.quarkus;