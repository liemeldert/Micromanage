//
//  JSONValue.swift
//  micromanaged
//
//  Created by Liem Eldert on 2026/10/05.
//

import Foundation

nonisolated indirect enum JSONValue: Codable, Sendable, Equatable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case null
    case array([JSONValue])
    case object([String: JSONValue])

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "unsupported JSON value")
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value):
            try container.encode(value)
        case .number(let value):
            try container.encode(value)
        case .bool(let value):
            try container.encode(value)
        case .null:
            try container.encodeNil()
        case .array(let value):
            try container.encode(value)
        case .object(let value):
            try container.encode(value)
        }
    }

    init?(any value: Any) {
        switch value {
        case let text as String:
            self = .string(text)
        case let number as NSNumber:
            if CFGetTypeID(number as CFTypeRef) == CFBooleanGetTypeID() {
                self = .bool(number.boolValue)
            } else {
                self = .number(number.doubleValue)
            }
        case let date as Date:
            self = .string(ISO8601DateFormatter().string(from: date))
        case let list as [Any]:
            self = .array(list.compactMap { JSONValue(any: $0) })
        case let dict as [String: Any]:
            var out: [String: JSONValue] = [:]
            for (key, item) in dict {
                if let converted = JSONValue(any: item) {
                    out[key] = converted
                }
            }
            self = .object(out)
        case is NSNull:
            self = .null
        default:
            return nil
        }
    }

    var stringValue: String? {
        if case .string(let value) = self {
            return value
        }
        return nil
    }

    var intValue: Int? {
        if case .number(let value) = self {
            return Int(value)
        }
        if case .string(let text) = self {
            return Int(text)
        }
        return nil
    }

    var boolValue: Bool? {
        if case .bool(let value) = self {
            return value
        }
        return nil
    }

    var arrayValue: [JSONValue]? {
        if case .array(let value) = self {
            return value
        }
        return nil
    }

    var objectValue: [String: JSONValue]? {
        if case .object(let value) = self {
            return value
        }
        return nil
    }

    subscript(key: String) -> JSONValue? {
        objectValue?[key]
    }

    var stringList: [String] {
        arrayValue?.compactMap(\.stringValue) ?? []
    }
}
