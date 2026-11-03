#!/usr/bin/env python3
"""Build a pinned MIT upstream CLI for STAGING FILES ONLY. Never installs/reloads LuLu."""
from pathlib import Path
import hashlib
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'references/lulu-cli-review/main.swift'
EXPECTED = "84c0cec5e760a2020413ee11f3271f7ddeda5668e00bb18a959d97ad53f2ea65"

def patched_source(source):
    # Current LuLu archives store this enum as an NSNumber object, not a primitive Bool.
    source = source.replace('@objc var isEndpointAddrRegex: Bool = false', '@objc var isEndpointAddrRegex: Int = 0')
    source = source.replace('isEndpointAddrRegex = decoder.decodeBool(forKey: "isEndpointAddrRegex")',
                            'isEndpointAddrRegex = decoder.decodeObject(of: NSNumber.self, forKey: "isEndpointAddrRegex")?.intValue ?? 0')
    source = source.replace('encoder.encode(isEndpointAddrRegex, forKey: "isEndpointAddrRegex")',
                            'encoder.encode(NSNumber(value: isEndpointAddrRegex), forKey: "isEndpointAddrRegex")')
    source = source.replace('rule.isEndpointAddrRegex = isRegex', 'rule.isEndpointAddrRegex = isRegex ? 1 : 0')
    source = source.replace('rule.isEndpointAddrRegex ? " [REGEX]" : ""', 'rule.isEndpointAddrRegex != 0 ? " [REGEX]" : ""')
    source = source.replace('let RULES_FILE = "/Library/Objective-See/LuLu/rules.plist"', '''let RULES_FILE: String = {
        guard getuid() != 0, let path = ProcessInfo.processInfo.environment["GUARD_STAGING_RULES"] else {
            fputs("Staging only: run without sudo and provide GUARD_STAGING_RULES.\\n", stderr); exit(64)
        }
        let supplied = URL(fileURLWithPath: path)
        let parent = supplied.deletingLastPathComponent().resolvingSymlinksInPath()
        let url = parent.appendingPathComponent(supplied.lastPathComponent)
        let staging = URL(fileURLWithPath: NSTemporaryDirectory()).resolvingSymlinksInPath().path + "/"
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        guard url.path.hasPrefix(staging), url.lastPathComponent == "staged-rules.plist",
              attributes?[.type] as? FileAttributeType == .typeRegular else {
            fputs("Refusing to access anything outside the temporary staging directory.\\n", stderr); exit(64)
        }
        return url.path
    }()''')
    source = source.replace('    let classes: [AnyClass] = [NSDictionary.self', '    // Refuse archives with unknown Rule fields instead of silently dropping them.\n    do {\n        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String:Any]\n        guard let objects = plist?["$objects"] as? [Any] else { return nil }\n        let known = Set(["$class", "key", "uuid", "pid", "path", "name", "csInfo", "endpointAddr", "endpointHost", "isEndpointAddrRegex", "endpointPort", "type", "scope", "action", "isDisabled", "creation", "expiration"])\n        for case let item as [String:Any] in objects where item["uuid"] != nil && item["endpointAddr"] != nil {\n            guard Set(item.keys).isSubset(of: known) else {\n                fputs("Unknown Rule schema; refusing lossy conversion.\\n", stderr)\n                return nil\n            }\n        }\n    } catch { return nil }\n    let classes: [AnyClass] = [NSDictionary.self')
    start = source.index('case "reload":')
    end = source.index('case "help",', start)
    source = source[:start] + '''case "reload":
        fputs("Reload is deliberately unavailable in the staging tool.\\n", stderr)
        exit(64)

''' + source[end:]
    assert 'kill.arguments' not in source
    assert 'let RULES_FILE = "/Library' not in source
    return '// Adapted from woop/lulu-cli, MIT; license in references/lulu-cli-review/LICENSE.\n' + source

def build(destination):
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != EXPECTED:
        raise RuntimeError("Pinned upstream source changed; refusing to build without review")
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='guard-staging-cli-build-') as temp:
        file = Path(temp) / 'main.swift'
        file.write_text(patched_source(SOURCE.read_text()))
        result = subprocess.run(['/usr/bin/xcrun', 'swiftc', '-module-cache-path', str(Path(temp)/'ModuleCache'), str(file), '-o', str(destination)],
                                capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr[-4000:])
    return destination

if __name__ == '__main__':
    target = Path.home() / 'Library/Caches/ClaudeGuardDevelopment/lulu-staging-cli'
    print(build(target))
    print('Staging-only binary. No system file was changed; no extension was restarted.')
