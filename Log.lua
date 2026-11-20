-- Roblox Mobile Exploit Analyzer & Log Generator
-- Optimized for Delta/Executor on Mobile
-- Usage: Paste into executor and run. Interact with the game. All output is consolidated into a single string at the end for easy copying.

local HttpService = game:GetService("HttpService")
local RunService = game:GetService("RunService")
local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Workspace = workspace

local LocalPlayer = Players.LocalPlayer
local LOG_BUFFER = {}
local MAX_LOG_ENTRIES = 200 -- Prevents memory leak if game is very verbose

-- 1. UTILITY: Log to buffer
local function log(msg, level)
    level = level or "INFO"
    local timestamp = os.date("%H:%M:%S")
    local entry = string.format("[%s] [%s] %s", timestamp, level, tostring(msg))
    
    -- Add to buffer
    if #LOG_BUFFER < MAX_LOG_ENTRIES then
        LOG_BUFFER[#LOG_BUFFER + 1] = entry
    else
        -- If buffer is full, replace the oldest entry (or just ignore new ones, but replacing keeps recent context)
        table.remove(LOG_BUFFER, 1)
        LOG_BUFFER[#LOG_BUFFER + 1] = entry
    end
    
    -- Also print to console for immediate feedback
    print(entry)
end

-- 2. UTILITY: Safe GetChildren
local function safeGetChildren(instance)
    if not instance then return {} end
    return instance:GetChildren()
end

-- 3. UTILITY: Truncate Source Code
local function getSnippet(source, length)
    if not source then return "" end
    return source:sub(1, length)
end

-- 4. DATA STRUCTURES
local analysisData = {
    remotes = {},
    modules = {},
    localScripts = {},
    uiFrameworks = {},
    patterns = {
        networking = 0,
        ui = 0,
        physics = 0,
        datastores = 0,
        antiExploit = 0
    },
    metadata = {
        placeId = game.PlaceId,
        universeId = game.UniverseId,
        serverId = game.Server,
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ")
    }
}

-- 5. CORE: TRAVERSE INSTANCE TREE
local function traverseInstance(instance, path, depth)
    if depth > 4 then return end
    
    local className = instance.ClassName
    local fullName = path or instance:GetFullName()
    
    if instance:IsA("RemoteEvent") or instance:IsA("RemoteFunction") then
        analysisData.remotes[#analysisData.remotes + 1] = {
            name = instance.Name,
            path = fullName,
            type = className
        }
        analysisData.patterns.networking = analysisData.patterns.networking + 1
        log("Found " .. className .. ": " .. fullName, "REMOTE")
        
        -- Hook for live monitoring
        if instance:IsA("RemoteEvent") then
            local originalFire = instance.FireServer
            instance.FireServer = function(...)
                local args = table.concat({...}, ", ")
                log("FIRE SERVER: " .. instance.Name .. " | Args: " .. args, "NET")
                return originalFire(instance, ...)
            end
            
            -- Also hook OnClientEvent to see server->client communication
            local originalConnect = instance.Connect
            -- Note: RemoteEvent.OnClientEvent is a property, not a method we can easily monkey-patch directly without losing original listeners.
            -- Instead, we'll wrap the event itself if possible, but simpler is to just log FireServer and rely on user interaction for OnClientEvent.
            -- For a more robust hook, we'd need to re-create the event, which is complex. 
            -- Let's stick to FireServer for now as it's the most common exploit vector (client->server).
        end
    end
    
    if instance:IsA("ModuleScript") then
        local source = instance.Source
        analysisData.modules[#analysisData.modules + 1] = {
            name = instance.Name,
            path = fullName,
            length = #source,
            snippet = getSnippet(source, 200)
        }
        log("Module: " .. fullName .. " (Size: " .. #source .. ")", "MODULE")
    end
    
    if instance:IsA("LocalScript") then
        local source = instance.Source
        analysisData.localScripts[#analysisData.localScripts + 1] = {
            name = instance.Name,
            path = fullName,
            length = #source,
            snippet = getSnippet(source, 200)
        }
        log("LocalScript: " .. fullName, "LOCAL")
    end
    
    if instance:IsA("ScreenGui") then
        analysisData.uiFrameworks[#analysisData.uiFrameworks + 1] = {
            name = instance.Name,
            path = fullName
        }
        analysisData.patterns.ui = analysisData.patterns.ui + 1
        log("ScreenGui: " .. fullName, "UI")
    end
    
    for _, child in ipairs(safeGetChildren(instance)) do
        traverseInstance(child, fullName .. "/" .. child.Name, depth + 1)
    end
end

-- 6. ANALYSIS: PATTERN DETECTION
local function analyzePatterns()
    local keywords = {
        physics = {"BodyVelocity", "BodyGyro", "Motor6D", "AssemblyLinearVelocity"},
        datastores = {"DataStoreService", "GetAsync", "UpdateAsync", "SetAsync"},
        antiExploit = {"GetRenderFps", "GetMouse", "UserInputService", "BindToRenderStep"}
    }
    
    local allScripts = {}
    for _, m in ipairs(analysisData.modules) do allScripts[#allScripts+1] = m end
    for _, l in ipairs(analysisData.localScripts) do allScripts[#allScripts+1] = l end
    
    for _, script in ipairs(allScripts) do
        local source = script.snippet
        for category, kws in pairs(keywords) do
            for _, kw in ipairs(kws) do
                if source:find(kw, 1, true) then
                    analysisData.patterns[category] = analysisData.patterns[category] + 1
                end
            end
        end
    end
end

-- 7. GENERATE: FINAL REPORT STRING
local function generateReport()
    local report = {}
    local function addLine(line)
        report[#report + 1] = line
    end
    
    addLine("========================================")
    addLine("ROBLOX EXPLOIT ANALYSIS REPORT")
    addLine("========================================")
    addLine("Place ID: " .. game.PlaceId)
    addLine("Universe ID: " .. game.UniverseId)
    addLine("Server ID: " .. game.Server)
    addLine("Timestamp: " .. os.date("!%Y-%m-%dT%H:%M:%SZ"))
    addLine("========================================")
    
    addLine("")
    addLine("--- SUMMARY ---")
    addLine("Total Remotes: " .. #analysisData.remotes)
    addLine("Total Modules: " .. #analysisData.modules)
    addLine("Total LocalScripts: " .. #analysisData.localScripts)
    addLine("Total ScreenGuis: " .. #analysisData.uiFrameworks)
    addLine("")
    
    addLine("--- PATTERNS ---")
    for k, v in pairs(analysisData.patterns) do
        addLine(string.format("%s: %d", k, v))
    end
    addLine("")
    
    addLine("--- TOP MODULES (Largest) ---")
    table.sort(analysisData.modules, function(a, b) return a.length > b.length end)
    for i = 1, math.min(5, #analysisData.modules) do
        addLine(string.format("%d. %s (%s) - %d bytes", i, analysisData.modules[i].name, analysisData.modules[i].path, analysisData.modules[i].length))
    end
    addLine("")
    
    addLine("--- REMOTES FOUND ---")
    for i, r in ipairs(analysisData.remotes) do
        if i <= 50 then -- Limit output
            addLine(string.format("%s: %s", r.type, r.path))
        else
            addLine("... and " .. (#analysisData.remotes - 50) .. " more")
            break
        end
    end
    addLine("")
    
    addLine("--- LIVE NETWORK LOG ---")
    addLine("Captured " .. #LOG_BUFFER .. " network events during analysis.")
    addLine("Recent Events:")
    -- Print last 20 entries from log buffer
    local startIdx = math.max(1, #LOG_BUFFER - 19)
    for i = startIdx, #LOG_BUFFER do
        addLine(LOG_BUFFER[i])
    end
    addLine("")
    addLine("========================================")
    addLine("END OF REPORT")
    addLine("========================================")
    
    return table.concat(report, "\n")
end

-- 8. MAIN EXECUTION
local function main()
    log("Starting Mobile Exploit Analysis...", "MAIN")
    log("Place ID: " .. game.PlaceId .. " | Universe ID: " .. game.UniverseId, "META")
    
    -- 1. Initial Scan of ReplicatedStorage
    log("Scanning ReplicatedStorage...", "SCAN")
    traverseInstance(ReplicatedStorage, "ReplicatedStorage", 0)
    
    -- 2. Scan Workspace (Top-level only)
    log("Scanning Workspace (Top-level)...", "SCAN")
    traverseInstance(Workspace, "Workspace", 0)
    
    -- 3. Scan PlayerGui
    local playerGui = LocalPlayer:FindFirstChild("PlayerGui")
    if playerGui then
        log("Scanning PlayerGui...", "SCAN")
        traverseInstance(playerGui, "PlayerGui", 0)
    end
    
    -- 4. Analyze Patterns
    log("Analyzing Patterns...", "ANALYSIS")
    analyzePatterns()
    
    -- 5. Wait for user interaction
    log("Analysis complete. Interact with the game for 30-60 seconds to capture network traffic.", "INFO")
    log("Press 'R' in your executor or wait 60 seconds to generate the final report.", "INFO")
    
    -- Wait for user to press 'R' or timeout after 60 seconds
    local userInput = game:GetService("UserInputService")
    local userRequestedReport = false
    local startTime = tick()
    
    -- Poll for user input
    while not userRequestedReport and (tick() - startTime) < 60 do
        if userInput:IsKeyDown(Enum.KeyCode.R) then
            userRequestedReport = true
        end
        task.wait(0.1)
    end
    
    if userRequestedReport then
        log("User requested report generation.", "INFO")
    else
        log("Timeout reached. Generating report.", "INFO")
    end
    
    -- 6. Generate and print final report
    local report = generateReport()
    log("Final Report Generated. Copy from below.", "DONE")
    print(report)
    
    -- Return the report for easy copying
    return report
end

-- Execute
local report = main()
return report
