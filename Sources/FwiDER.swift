//  Project name: FwiSecurity
//  File name   : FwiDER.swift
//
//  Author      : Phuc, Tran Huu
//  Created date: 1/29/17
//  Version     : 1.00
//  --------------------------------------------------------------
//  Copyright © 2012, 2017 Fiision Studio.
//  All Rights Reserved.
//  --------------------------------------------------------------
//
//  Permission is hereby granted, free of charge, to any person obtaining  a  copy
//  of this software and associated documentation files (the "Software"), to  deal
//  in the Software without restriction, including without limitation  the  rights
//  to use, copy, modify, merge,  publish,  distribute,  sublicense,  and/or  sell
//  copies of the Software,  and  to  permit  persons  to  whom  the  Software  is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF  ANY  KIND,  EXPRESS  OR
//  IMPLIED, INCLUDING BUT NOT  LIMITED  TO  THE  WARRANTIES  OF  MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO  EVENT  SHALL  THE
//  AUTHORS OR COPYRIGHT HOLDERS  BE  LIABLE  FOR  ANY  CLAIM,  DAMAGES  OR  OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING  FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN  THE
//  SOFTWARE.
//
//
//  Disclaimer
//  __________
//  Although reasonable care has been taken to  ensure  the  correctness  of  this
//  software, this software should never be used in any application without proper
//  testing. Fiision Studio disclaim  all  liability  and  responsibility  to  any
//  person or entity with respect to any loss or damage caused, or alleged  to  be
//  caused, directly or indirectly, by the use of this software.

import Foundation
/// Optional
import FwiCore


public struct FwiDER {

    // MARK: Class's constructors
    internal init(withIdentifier i: UInt8 = 0) {
        identifier = i
        derClass = FwiGetDerClass(identifier)
        derValue = FwiGetDerValue(identifier)
        
        if derClass == .universal {
//            if (derValue == .bitString       || derValue == .octetString      ||
//                derValue == .null            || derValue == .objectIdentifier ||
//                derValue == .numericString   || derValue == .printableString  ||
//                derValue == .t61String       || derValue == .utf8String       ||
//                derValue == .ia5String       || derValue == .utcTime          ||
//                derValue == .generalizedTime || derValue == .graphicString    ||
//                derValue == .visibleString   || derValue == .generalString    ||
//                derValue == .universalString || derValue == .bmpString)
//            {
//                // Do nothing
//            } else
            if derValue == .integer  || derValue == .enumerated {
                integer = 0
            } else if derValue == .sequence || derValue == .set {
                children = []
            } else if derValue == .boolean {
                boolean = false
            }
        } else {
            if isStructure {
                children = []
            }
        }
    }
    
    // MARK: Class's properties
    public var content: Data? {
        get {
            if isStructure {
                guard let children = children, children.count > 0 else {
                    return nil
                }
                
                return children.reduce(Data(capacity: length), { (c, child) -> Data in
                    guard let data = child.encode() else {
                        return c
                    }
                    var content = c
                    
                    content.append(data)
                    return content
                })
            } else {
                guard let content = content_, content.count > 0 else {
                    return nil
                }
                
                if derValue != .bitString {
                    return content
                } else {
                    return content.subdata(in: Range<Data.Index>(uncheckedBounds: (lower: 1, upper: content.count)))
                }
            }
        }
        set {
            /* Condition validation */
            guard !isStructure && derValue != .null else {
                return
            }
            
            /* Condition validation: Validate newValue */
            guard let value = newValue, value.count > 0 else {
                return
            }
            
            // Sepecial case for boolean as it is only accept 1 byte length
            if derValue == .boolean {
                if content_ == nil {
                    content_ = value.subdata(in: Range<Data.Index>(uncheckedBounds: (lower: 0, upper: 1)))
                } else {
                    content_?[0] = value[0]
                }
            } else {
                content_ = value
            }
        }
    }
    
    public var count: Int {
        guard isStructure else {
            return 0
        }
        return children?.count ?? 0
    }
    public var length: Int {
        if isStructure {
            let total = children?.reduce(0, { (t, child) -> Int in
                let length = child.length
                var total = t
                
                if length > 0x7f {
                    if length < 0x100 {
                        total += 3
                    } else if length < 0x10000 {
                        total += 4
                    } else if length < 0x1000000 {
                        total += 5
                    } else {
                        total += 6
                    }
                } else {
                    total += 2
                }
                total += length
                return total
            })
            return total ?? 0
        } else {
            return content_?.count ?? 0
        }
    }
    public var isStructure: Bool {
        return (((identifier & 0x20) >> 5) == 1)
    }
    
    /// Primitive used.
    internal var derClass: FwiDERClass
    internal var derValue: FwiDERValue
    internal var identifier: UInt8
    /// Structure used.
    internal var content_: Data?
    internal var children: [FwiDER]?
    /// Internal used.
    fileprivate lazy var dateFormat: DateFormatter = {
        let dateFormat = DateFormatter()
        
        dateFormat.timeZone = TimeZone(identifier: "UTC")
        dateFormat.dateStyle = .none
        dateFormat.timeStyle = .none
        dateFormat.dateFormat = nil
        return dateFormat
    }()
    
    // MARK: Class's public methods
    /// Encode DER to data.
    public func encode() -> Data? {
        guard var content = isStructure ? self.content : content_, content.count > 0 else {
            return Data(bytes: [identifier, 0x00])
        }
        
        let length = UInt32(content.count)
        var data: Data
        
        if length > 0x7f {
            if length < 0x100 {
                data = Data(bytes: [identifier, FwiDERLength.level1.rawValue, UInt8(length)])
            } else if length < 0x10000 {
                let t1 = UInt32(integerLiteral: 0xff00)
                let t2 = UInt32(integerLiteral: 0x00ff)
                data = Data(bytes: [identifier, FwiDERLength.level2.rawValue, UInt8((length & t1) >> 8), UInt8(length & t2)])
            } else if length < 0x1000000 {
                let t1 = UInt32(integerLiteral: 0xff0000)
                let t2 = UInt32(integerLiteral: 0x00ff00)
                let t3 = UInt32(integerLiteral: 0x0000ff)
                data = Data(bytes: [identifier, FwiDERLength.level3.rawValue, UInt8((length & t1) >> 16), UInt8((length & t2) >> 8), UInt8(length & t3)])
            } else {
                let t1 = UInt32(integerLiteral: 0xff000000)
                let t2 = UInt32(integerLiteral: 0x00ff0000)
                let t3 = UInt32(integerLiteral: 0x0000ff00)
                let t4 = UInt32(integerLiteral: 0x000000ff)
                data = Data(bytes: [identifier, FwiDERLength.level4.rawValue, UInt8((length & t1) >> 24), UInt8((length & t2) >> 16), UInt8((length & t3) >> 8), UInt8(length & t4)])
            }
        } else {
            data = Data(bytes: [identifier, UInt8(length)])
        }
        
        data.append(content)
        return data
    }

    /// Encode DER to base64 data.
    public func encodeBase64Data() -> Data? {
        return encode()?.encodeBase64Data()
    }
    
    /// Encode DER to base64 string.
    public func encodeBase64String() -> String? {
        return encodeBase64Data()?.toString()
        
    }
    
    // MARK: Class's private methods
}

// MARK: Creation
public extension FwiDER {

    public static func null() -> FwiDER {
        let o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .null))
        return o
    }
    
    public static func boolean(withValue v: Bool = false) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .boolean))
        o.boolean = v
        return o
    }
    
    public static func integer(withInt i: Int = 0) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .integer))
        o.integer = i
        return o
    }
    public static func integer(withData d: Data?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .integer))
        o.bigInt = nil
        //    [o setBigInt:[FwiBigInt bigIntWithData:value shouldReverse:YES]];
        return o
    }
    public static func integer(withBigInt bigInt: FwiBigInt?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .integer))
        o.bigInt = bigInt
        return o
    }
    
    public static func enumerated(withInt i: Int = 0) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .enumerated))
        o.integer = i
        return o
    }
    public static func enumerated(withData d: Data?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .enumerated))
        o.bigInt = nil
        //    [o setBigInt:[FwiBigInt bigIntWithData:value shouldReverse:YES]];
        return o
    }
    public static func enumerated(withBigInt bigInt: FwiBigInt?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .enumerated))
        o.bigInt = bigInt
        return o
    }
    
    public static func bitString(withDER der: FwiDER?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .bitString))
        o.setBitString(withDER: der)
        return o
    }
    public static func bitString(withArray a: [FwiDER]?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .bitString))
        o.setBitString(withDER: FwiDER.sequence(withArray: a))
        return o
    }
    public static func bitString(withData d: Data? = nil, padding p: UInt8 = 0) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .bitString))
        o.setBitString(withData: d, padding: p)
        return o
    }
    
    public static func octetString(withDER der: FwiDER?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .octetString))
        o.setOctetString(withDER: der)
        return o
    }
    public static func octetString(withArray a: [FwiDER]?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .octetString))
        o.setOctetString(withDER: FwiDER.sequence(withArray: a))
        return o
    }
    public static func octetString(withData d: Data? = nil) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .octetString))
        o.setOctetString(withData: d)
        return o
    }
    
    public static func utf8String(withData d: Data?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .utf8String))
        o.setString(withData: d)
        return o
    }
    public static func utf8String(withString s: String? = nil) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .utf8String))
        o.string = s
        return o
    }
    
    public static func numericString(withData d: Data?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .numericString))
        o.setString(withData: d)
        return o
    }
    public static func numericString(withString s: String? = nil) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .numericString))
        o.string = s
        return o
    }
    
    public static func printableString(withData d: Data?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .printableString))
        o.setString(withData: d)
        return o
    }
    public static func printableString(withString s: String? = nil) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .numericString))
        o.string = s
        return o
    }
    
    public static func t61String(withData d: Data?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .t61String))
        o.setString(withData: d)
        return o
    }
    public static func t61String(withString s: String? = nil) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .t61String))
        o.string = s
        return o
    }
    
    public static func ia5String(withData d: Data?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .ia5String))
        o.setString(withData: d)
        return o
    }
    public static func ia5String(withString s: String? = nil) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .ia5String))
        o.string = s
        return o
    }
    
    public static func graphicString(withData d: Data?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .graphicString))
        o.setString(withData: d)
        return o
    }
    public static func graphicString(withString s: String? = nil) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .graphicString))
        o.string = s
        return o
    }
    
    public static func visibleString(withData d: Data?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .visibleString))
        o.setString(withData: d)
        return o
    }
    public static func visibleString(withString s: String? = nil) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .visibleString))
        o.string = s
        return o
    }
    
    public static func generalString(withData d: Data?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .generalString))
        o.setString(withData: d)
        return o
    }
    public static func generalString(withString s: String? = nil) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .generalString))
        o.string = s
        return o
    }
    
    public static func universalString(withData d: Data?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .universalString))
        o.setString(withData: d)
        return o
    }
    public static func universalString(withString s: String? = nil) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .universalString))
        o.string = s
        return o
    }
    
    public static func bmpString(withData d: Data?) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .bmpString))
        o.setString(withData: d)
        return o
    }
    public static func bmpString(withString s: String? = nil) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .bmpString))
        o.string = s
        return o
    }
    
    public static func objectIdentifier(withString s: String? = nil) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .objectIdentifier))
        o.objectIdentifier = s
        return o
    }
    
    public static func utcTime(withTime t: Date? = Date()) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .utcTime))
        o.time = t
        return o
    }
    
    public static func generalizedTime(withTime t: Date? = Date()) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .generalizedTime))
        o.time = t
        return o
    }
    
    public static func sequence(withArray a: [FwiDER]? = nil) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .sequence, additionalValue: 0x20))
        o.set(newDERs: a)
        return o
    }
    
    public static func set(withArray a: [FwiDER]? = nil) -> FwiDER {
        var o = FwiDER(withIdentifier: FwiDERClass.universal.identifier(value: .set, additionalValue: 0x20))
        o.set(newDERs: a)
        return o
    }

//+ (__autoreleasing FwiDer *)derWithIdentifier:(uint8_t)identifier {
//return FwiAutoRelease([[FwiDer alloc] initWithIdentifier:identifier]);
//}
//+ (__autoreleasing FwiDer *)derWithIdentifier:(uint8_t)identifier array:(NSArray *)array {
//__autoreleasing FwiDer *o = [FwiDer derWithIdentifier:identifier];
//[o setDersWithArray:array];
//return o
//}
//+ (__autoreleasing FwiDer *)derWithIdentifier:(uint8_t)identifier content:(NSData *)content {
//__autoreleasing FwiDer *o = [FwiDer derWithIdentifier:identifier];
//[o setContent:content];
//return o
//}


}

// MARK: Collection
public extension FwiDER {
    
    /// Add new DER to current collection.
    ///
    /// - parameter DER (required): new DER object
    public mutating func add(newDER d: FwiDER?) {
        /* Condition validation */
        guard let d = d, isStructure else {
            return
        }
        children?.append(d)
    }
    
    /// Add multiple new DERs to current collection.
    ///
    /// - parameter DERs (required): multiple new DER objects
    public mutating func add(newDERs array: [FwiDER]?) {
        /* Condition validation */
        guard let array = array, isStructure && array.count > 0 else {
            return
        }
        children?.append(contentsOf: array)
    }
    
    /// Reset current collection then add new DER to new collection.
    ///
    /// - parameter DER (required): new DER object
    public mutating func set(newDER d: FwiDER?) {
        children?.removeAll()
        add(newDER: d)
    }
    
    /// Reset current collection then add multiple new DERs to new collection.
    ///
    /// - parameter DERs (required): multiple new DER objects
    public mutating func set(newDERs array: [FwiDER]?) {
        children?.removeAll()
        add(newDERs: array)
    }
    
    /// Get DER at index, return null if this DER is not structured.
    ///
    /// - parameter index (required): DER's index
    public subscript(index: Int) -> FwiDER? {
        get {
            /* Condition validation */
            guard let children = children, isStructure && index >= 0 && index < children.count else {
                return nil
            }
            return children[index]
        }
        set {
            /* Condition validation */
            guard let c = children, isStructure && index >= 0 else {
                return
            }
            
            guard let newValue = newValue else {
                if index < c.count {
                    children?.remove(at: index)
                }
                return
            }
            
            if index >= c.count {
                children?.append(newValue)
            } else {
                children?[index] = newValue
            }
        }
    }
    
    /// Get DER for DER path, return null if this DER is not structured.
    ///
    /// - parameter index (required): DER's path (e.g: 0/1/2)
    public subscript(path: String) -> FwiDER? {
        get {
            /* Condition validation */
            guard let children = children, isStructure && children.count > 0 && path.matchPattern("^\\d+(/\\d+)*$") else {
                return nil
            }
            
            let tokens = path.split("/")
            let o = tokens.reduce(self) { (origin, token) -> FwiDER in
                guard let index = Int(token), let o = origin[index] else {
                    return origin
                }
                return o
            }
            return o
        }
    }
}

// MARK: Primitive
public extension FwiDER {
    
    /// Property boolean.
    public var boolean: Bool {
        get {
            guard let content = content_, content.count >= 1 else {
                return false
            }
            return (content[0] == 0xff)
        }
        set {
            guard derValue == .boolean else {
                return
            }
            content = Data(bytes: [newValue ? 0xff : 0x00])
        }
    }
    
    /// Property integer.
    public var integer: Int {
        get {
            guard let content = content_, content.count > 0 else {
                return 0
            }
            var integer = Int(content[0])
            
            let length  = min(content.count, MemoryLayout<Int>.size)
            for i in 1 ..< length {
                integer <<= 8
                integer |= Int(content[i])
            }
            return integer
        }
        set {
            guard derValue == .integer || derValue == .enumerated else {
                return
            }
//            [self setBigInt:[FwiBigInt bigIntWithInteger:value]];
        }
    }
    
    /// Property big integer.
    public var bigInt: FwiBigInt? {
        get {
            guard let content = content_, content.count > 0 else {
                return nil
            }
//            return [FwiBigInt bigIntWithData:_content shouldReverse:YES];
            return nil
        }
        set {
            guard derValue == .integer || derValue == .enumerated else {
                return
            }
//            [self setContent:[value encode]];
        }
    }
    
    /// Property time.
    public var time: Date? {
        mutating get {
            defer { dateFormat.dateFormat = nil }
            
            var charSet = CharacterSet(charactersIn: "Z")
            var sc = string?.uppercased()
            
            if let range = sc?.rangeOfCharacter(from: charSet) /*, range.upperBound != NSNotFound */ {
                sc = sc?.substring(with: range)
            }
            
            if derValue == .generalizedTime {
//                var charSet = haracterSet(charactersIn: ".")
//                range = [sc rangeOfCharacterFromSet:charSet];
//                if (range.location != NSNotFound) {
//                    if (range.location == 14) {
//                        if (sc.length == 16) {
//                            [dateFormat setDateFormat:@"yyyyMMddHHmmss.S"];
//                        }
//                        else if (sc.length == 17) {
//                            [dateFormat setDateFormat:@"yyyyMMddHHmmss.SS"];
//                        }
//                        else if (sc.length == 18) {
//                            [dateFormat setDateFormat:@"yyyyMMddHHmmss.SSS"];
//                        }
//                    }
//                }
//                else {
//                    if (sc.length == 8) {
//                        [dateFormat setDateFormat:@"yyyyMMdd"];
//                    }
//                    else if (sc.length == 12) {
//                        [dateFormat setDateFormat:@"yyyyMMddHHmm"];
//                    }
//                    else if (sc.length == 14) {
//                        [dateFormat setDateFormat:@"yyyyMMddHHmmss"];
//                    }
//                }
            } else if derValue == .utcTime {
                if sc?.length() == 6 {
                    dateFormat.dateFormat = "yyMMdd"
                } else if sc?.length() == 10 {
                    dateFormat.dateFormat = "yyMMddHHmm"
                } else if sc?.length() == 12 {
                    dateFormat.dateFormat = "yyMMddHHmmss"
                }
            }
            
//            if (dateFormat.dateFormat || dateFormat.dateFormat.length > 0) return [dateFormat dateFromString:sc];
//            else
            return nil;
        }
        set {
            guard let date = newValue, derValue == .generalizedTime || derValue == .utcTime else {
                return
            }
            defer { dateFormat.dateFormat = nil }
            
            var time: String
            if derValue == .generalizedTime {
                dateFormat.dateFormat = "yyyyMMddHHmmss.SSS"
                time = dateFormat.string(from: date)
                
                if time.hasSuffix("000") {
                    time = "\(time.substring(startIndex: 0, reverseIndex: -4))Z"
                } else {
                    time = "\(time)Z"
                }
            } else {
                dateFormat.dateFormat = "yyMMddHHmmss"
                time = "\(dateFormat.string(from: date))Z"
            }
            content = time.toData()
        }
    }
    
    /// Property object identifier.
    public var objectIdentifier: String? {
        get {
            guard let content = content_, derValue == .objectIdentifier else {
                return nil
            }
            
            // Process first byte
            var builder: String
            if content[0] < 40 {
                builder = String(format: "0.%d", content[0])
            } else if content[0] < 80 {
                builder = String(format: "1.%d", content[0] - 40)
            } else if content[0] < 120 {
                builder = String(format: "2.%d", content[0] - 80)
            } else {
                builder = String(format: "3.%d", content[0] - 120)
            }
            
            // Process the rest
            var i = 1
            while (i < content.count) {
                var j = 0
                while ((content[i + j] & 0x80) != 0) { j += 1 }
                
                var n = Double(content[i + j])
                for k in 0 ..< j {
                    n += Double(content[(i + j) - k - 1]  & 0x0f) * pow(Double(0x80), Double(k + 1))
                    n += Double((content[(i + j) - k - 1] & 0x70) >> 4) * pow(Double(0x80), Double(k + 1)) * 0x10
                }
                
                builder.append(".\(Int64(round(n)))")
                i += (j + 1)
            }
            
            return builder
        }
        set {
            guard let oid = newValue, oid.length() > 0 && derValue == .objectIdentifier else {
                return
            }
            var data = Data(capacity: 10)
            let values = oid.split(".")
            var a: UInt8  = 0
            var b: UInt32 = 0
            
            for idx in 0 ..< values.count {
                if idx == 0 {
                    a = UInt8(values[idx]) ?? 0
                } else if idx == 1 {
                    a = (a * 40) + (UInt8(values[idx]) ?? 0)
                    data.append(a)
                } else {
                    b = UInt32(values[idx]) ?? 0
                    
                    if b < 0x80 {
                        data.append(UInt8(b))
                    } else if b < 0x4000 {
                        data.append(UInt8(((b & 0x3f80) >> 7) | 0x80))
                        data.append(UInt8(b & 0x7f))
                    } else if (b < 0x200000) {
                        data.append(UInt8(((b & 0x1fc000) >> 14) | 0x80))
                        data.append(UInt8(((b & 0x3f80) >> 7) | 0x80))
                        data.append(UInt8(b & 0x7f))
                    } else {
                        data.append(UInt8(((b & 0xfe00000) >> 21) | 0x80))
                        data.append(UInt8(((b & 0x1fc000) >> 14) | 0x80))
                        data.append(UInt8(((b & 0x3f80) >> 7) | 0x80))
                        data.append(UInt8(b & 0x7f))
                    }
                }
            }
            content = data
        }
    }
    
    /// Property string.
    public var string: String? {
        get {
            guard let content = content_ else {
                return nil
            }
            
            if derClass == .universal {
                switch derValue {
                case .null:
                    return ""
                    
                case .boolean:
                    return boolean ? "True" : "False"

                case .integer, .enumerated:
                    return bigInt?.description
                    
                case .bitString:
                    let data = content.subdata(in: Range<Data.Index>(uncheckedBounds: (lower: 1, upper: content.count)))
                    return data.encodeHexString()
                    
                case .octetString:
                    return content.encodeHexString()
                    
                case .objectIdentifier:
                    return objectIdentifier
                    
                case .universalString:
                    return "#\(content.encodeHexString() ?? "")"
                    
                case .bmpString:
                    var builder = ""
                    for i in stride(from: 0, to: content.count, by: 2) {
                        let unit = ((UInt16(content[i]) << 8) | UInt16(content[i + 1]))
                        guard let unicode = UnicodeScalar(unit) else {
                            continue
                        }
                        
                        let c = Character(unicode)
                        builder.append(c)
                    }
                    return builder
                    
                default:
                    return content.toString()
                }
            } else {
                return content.encodeHexString()
            }
        }
        set {
            /* Condition validation */
            guard
                derValue == .utf8String      || derValue == .numericString ||
                derValue == .printableString || derValue == .t61String     ||
                derValue == .ia5String       || derValue == .graphicString ||
                derValue == .visibleString   || derValue == .generalString ||
                derValue == .universalString || derValue == .bmpString
            else {
                return
            }
            
            /* Condition validation: validate input */
            guard let input = newValue, input.length() > 0 else {
                return
            }
            
            switch derValue {
                
            case .utf8String, .numericString, .printableString, .t61String, .ia5String, .graphicString, .visibleString, .generalString,.universalString:
                setString(withData: input.toData())
                
            case .bmpString:
                let data = input.utf16.reduce(Data(), { (bmpString, unit) -> Data in
                    let b1 = UInt8((unit & 0xff00) >> 8)
                    let b2 = UInt8(unit & 0x00ff)
                    var string = bmpString
                    
                    string.append(b1)
                    string.append(b2)
                    return string
                })
                setString(withData: data)
                
            default:
                break
            }
        }
    }
        
    /// Set string with data.
    public mutating func setString(withData d: Data?) {
        /* Condition validation */
        guard
            derValue == .utf8String      || derValue == .numericString ||
            derValue == .printableString || derValue == .t61String     ||
            derValue == .ia5String       || derValue == .graphicString ||
            derValue == .visibleString   || derValue == .generalString ||
            derValue == .universalString || derValue == .bmpString
        else {
            return
        }
        
        /* Condition validation: validate data */
        guard let data = d, data.count > 0 else {
            return
        }

        switch derValue {

        case .numericString:
            let isValid = data.reduce(true, { (currentFlag, unit) -> Bool in
                guard currentFlag else {
                    return false
                }
                let c = Character(UnicodeScalar(unit))
                return (("0" <= c && c <= "9") || c == " ")
            })
            if isValid { content = data }

        case .printableString:
            let isValid = data.reduce(true, { (currentFlag, unit) -> Bool in
                guard currentFlag else {
                    return false
                }
                let c = Character(UnicodeScalar(unit))
                return (("a" <= c && c <= "z") || ("A" <= c && c <= "Z") || ("0" <= c && c <= "9") || c == " " || c == "(" || c == ")" || c == "+" || c == "-" || c == "." || c == ":" || c == "=" || c == "?" || c == "/" || c == "," || c == "'")
            })
            if isValid { content = data }

        case .ia5String:
            let isValid = data.reduce(true, { (currentFlag, unit) -> Bool in
                guard currentFlag else {
                    return false
                }
                return (unit <= 0x007f)
            })
            if isValid { content = data }

        default:
            content = data
        }
    }

    /// Set Bit String.
    public mutating func setBitString(withData d: Data?, padding p: UInt8 = 0) {
        /* Condition validation */
        guard var data = d, data.count > 0 && derValue == .bitString else {
            return
        }
        data.insert(p, at: data.startIndex)
        content = data
    }
    public mutating func setBitString(withDER o: FwiDER?, padding p: UInt8 = 0) {
        /* Condition validation */
        guard let data = o?.encode(), data.count > 0 && derValue == .bitString else {
            return
        }
        setBitString(withData: data, padding: p)
    }
    
    /// Set Octet String.
    public mutating func setOctetString(withData d: Data?) {
        /* Condition validation */
        guard var data = d, data.count > 0 && derValue == .octetString else {
            return
        }
        content = data
    }
    public mutating func setOctetString(withDER o: FwiDER?) {
        /* Condition validation */
        guard let data = o?.encode(), data.count > 0 && derValue == .octetString else {
            return
        }
        content = data
    }
}
