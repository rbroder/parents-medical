// Usage: swift scripts/encrypt.swift [--new-password]
// Encrypts family.json into data.enc.json using the key in .password.
import CommonCrypto
import CryptoKit
import Foundation

let iterations = 600_000
let words = [
  "river", "lantern", "copper", "meadow", "falcon", "harbor", "pepper", "violet", "marble", "canyon",
  "thunder", "walnut", "orchid", "summit", "velvet", "anchor", "bamboo", "cobalt", "desert", "ember",
  "fjord", "glacier", "hazel", "island", "juniper", "kettle", "lagoon", "mango", "nectar", "olive",
  "pebble", "quartz", "raven", "saffron", "tundra", "umbrella", "valley", "willow", "yonder", "zephyr",
  "almond", "breeze", "cedar", "dolphin", "elm", "fennel", "garnet", "heron", "ivory", "jasmine",
  "kiwi", "lemon", "maple", "nutmeg", "oyster", "plum", "quill", "rosemary", "sparrow", "thistle",
  "tulip", "urchin", "vine", "wren", "yarrow", "zinnia", "acorn", "birch", "clover", "dune",
  "eagle", "fig", "ginger", "hickory", "iris", "jade", "kelp", "lilac", "moss", "nettle",
]

func randomBytes(_ count: Int) -> Data {
  var bytes = [UInt8](repeating: 0, count: count)
  precondition(SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess)
  return Data(bytes)
}

func deriveKey(password: String, salt: Data) -> Data {
  var key = [UInt8](repeating: 0, count: 32)
  let pw = Array(password.utf8)
  let status = salt.withUnsafeBytes { saltPtr in
    CCKeyDerivationPBKDF(
      CCPBKDFAlgorithm(kCCPBKDF2), password, pw.count,
      saltPtr.bindMemory(to: UInt8.self).baseAddress, salt.count,
      CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations), &key, 32)
  }
  precondition(status == 0)
  return Data(key)
}

let args = CommandLine.arguments
let root = FileManager.default.currentDirectoryPath
let passwordPath = "\(root)/.password"

if args.contains("--new-password") {
  let picked = (0..<7).map { _ -> String in
    var i = 0
    repeat {
      i = Int(randomBytes(1)[0])
    } while i >= 240
    return words[i % words.count]
  }
  try picked.joined(separator: "-").write(toFile: passwordPath, atomically: true, encoding: .utf8)
  try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: passwordPath)
  print("New password saved to .password")
}

let password = try String(contentsOfFile: passwordPath, encoding: .utf8)
  .trimmingCharacters(in: .whitespacesAndNewlines)
let plaintext = try Data(contentsOf: URL(fileURLWithPath: "\(root)/family.json"))
_ = try JSONSerialization.jsonObject(with: plaintext)

// Keep the salt across updates so a key remembered on a device keeps working.
let previous = (try? Data(contentsOf: URL(fileURLWithPath: "\(root)/data.enc.json")))
  .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
let keptSalt = args.contains("--new-password")
  ? nil : (previous?["salt"] as? String).flatMap { Data(base64Encoded: $0) }
let salt = keptSalt ?? randomBytes(16)
let iv = randomBytes(12)
let key = SymmetricKey(data: deriveKey(password: password, salt: salt))
let sealed = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(data: iv))

let output: [String: Any] = [
  "v": 1,
  "iterations": iterations,
  "salt": salt.base64EncodedString(),
  "iv": iv.base64EncodedString(),
  "data": (sealed.ciphertext + sealed.tag).base64EncodedString(),
]
let json = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
try json.write(to: URL(fileURLWithPath: "\(root)/data.enc.json"))
print("Encrypted \(plaintext.count) bytes into data.enc.json")
