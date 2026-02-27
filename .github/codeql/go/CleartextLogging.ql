/**
 * @name Clear-text logging of sensitive information (Pelican)
 * @description Logging sensitive information without encryption or hashing can
 *              expose it to an attacker. This is a Pelican-specific version of
 *              go/clear-text-logging that excludes fields that store file paths
 *              rather than secrets (S3SecretKeyfile, UIPasswordFile,
 *              PasswordLocation).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id go/clear-text-logging
 * @tags security
 *       external/cwe/cwe-312
 *       external/cwe/cwe-315
 *       external/cwe/cwe-359
 */

import go
import semmle.go.security.CleartextLogging
import CleartextLogging::Flow::PathGraph

/**
 * Holds if the source node refers to a field that stores a file path rather
 * than the secret itself (e.g. S3SecretKeyfile, UIPasswordFile,
 * PasswordLocation). These are false positives because logging a *path* does
 * not expose the secret contained in the file at that path.
 */
predicate isSafeFilepathField(CleartextLogging::Source source) {
  source
      .describe()
      .regexpMatch("(?i).*(" +
          "S3SecretKeyfile|" +
          "UIPasswordFile|" +
          "PasswordLocation" + ").*")
}

from CleartextLogging::Flow::PathNode source, CleartextLogging::Flow::PathNode sink
where
  CleartextLogging::Flow::flowPath(source, sink) and
  not isSafeFilepathField(source.getNode())
select sink.getNode(), source, sink, "$@ flows to a logging call.", source.getNode(),
  "Sensitive data returned by " + source.getNode().(CleartextLogging::Source).describe()
