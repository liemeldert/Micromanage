//
//  MenuBarIconState.swift
//  micromanage-extra
//
//  Created by Liem Eldert on 2026/10/05.
//

import Combine
import Foundation
import SwiftUI

// The menu bar symbol follows the admin state: plain while standard, filled while elevated, half while a request
// waits for approval. Under a debugger it is a ladybug, so a Debug run is never mistaken for the installed copy.
final class MenuBarIconState: ObservableObject {
    static let shared = MenuBarIconState()

    @Published var symbolName = "shield"

    func update(isAdmin: Bool, pending: Bool) {
        if isDebuggerAttached() {
            symbolName = "ladybug"
        } else if pending {
            symbolName = "shield.lefthalf.filled"
        } else if isAdmin {
            symbolName = "shield.fill"
        } else {
            symbolName = "shield"
        }
    }
}
