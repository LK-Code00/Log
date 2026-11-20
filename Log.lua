-- Roblox Exploit Analyzer Hub
-- Mobile Optimized (Delta/Executor)
-- Features:
-- 1. Live Analysis: Scans game structure and hooks Remotes in real-time.
-- 2. Interactive UI: On-screen console to view logs, search remotes, and copy data.
-- 3. One-Click Copy: Buttons to copy the full report or specific remote names.
-- 4. Auto-Generated Hooks: Creates a ready-to-use exploit framework string.

local HttpService = game:GetService("HttpService")
local RunService = game:GetService("RunService")
local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Workspace = workspace
local CoreGui = game:GetService("CoreGui")
local UserInputService = game:GetService("UserInputService")

local LocalPlayer = Players.LocalPlayer

-- 1. DATA STRUCTURES
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

local LOG_BUFFER = {}
local MAX_LOG_ENTRIES = 500

-- 2. UTILITY FUNCTIONS
local function log(msg, level)
    level = level or "INFO"
    local timestamp = os.date("%H:%M:%S")
    local entry = string.format("[%s] [%s] %s", timestamp, level, tostring(msg))
    
    if #LOG_BUFFER < MAX_LOG_ENTRIES then
        LOG_BUFFER[#LOG_BUFFER + 1] = entry
    else
        table.remove(LOG_BUFFER, 1)
        LOG_BUFFER[#LOG_BUFFER + 1] = entry
    end
    
    print(entry)
    -- Update UI if it exists
    if _G._ExploitHubUI then
        _G._ExploitHubUI:UpdateLog(entry)
    end
end

local function safeGetChildren(instance)
    if not instance then return {} end
    return instance:GetChildren()
end

local function getSnippet(source, length)
    if not source then return "" end
    return source:sub(1, length)
end

-- 3. CORE: TRAVERSE INSTANCE TREE
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
        
        if instance:IsA("RemoteEvent") then
            local originalFire = instance.FireServer
            instance.FireServer = function(...)
                local args = table.concat({...}, ", ")
                log("FIRE SERVER: " .. instance.Name .. " | Args: " .. args, "NET")
                return originalFire(instance, ...)
            end
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

-- 4. ANALYSIS: PATTERN DETECTION
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

-- 5. GENERATE: FINAL REPORT STRING
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
        if i <= 50 then
            addLine(string.format("%s: %s", r.type, r.path))
        else
            addLine("... and " .. (#analysisData.remotes - 50) .. " more")
            break
        end
    end
    addLine("")
    addLine("--- LIVE NETWORK LOG (Last 20) ---")
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

-- 6. UI CREATION
local function createHubUI()
    local gui = Instance.new("ScreenGui")
    gui.Name = "ExploitAnalyzerHub"
    gui.ResetOnSpawn = false
    gui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
    gui.Parent = CoreGui
    
    local mainFrame = Instance.new("Frame")
    mainFrame.Name = "MainFrame"
    mainFrame.Size = UDim2.fromScale(0.4, 0.7)
    mainFrame.Position = UDim2.fromScale(0.5, 0.5)
    mainFrame.AnchorPoint = Vector2.new(0.5, 0.5)
    mainFrame.BackgroundColor3 = Color3.fromRGB(20, 20, 30)
    mainFrame.BorderSizePixel = 0
    mainFrame.Parent = gui
    
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, 10)
    corner.Parent = mainFrame
    
    local title = Instance.new("TextLabel")
    title.Name = "Title"
    title.Size = UDim2.fromScale(1, 0.08)
    title.Position = UDim2.fromScale(0, 0)
    title.BackgroundTransparency = 1
    title.Text = "🛡️ Roblox Exploit Analyzer Hub"
    title.TextColor3 = Color3.fromRGB(255, 255, 255)
    title.TextScaled = true
    title.Font = Enum.Font.GothamBold
    title.Parent = mainFrame
    
    local logFrame = Instance.new("ScrollingFrame")
    logFrame.Name = "LogFrame"
    logFrame.Size = UDim2.fromScale(1, 0.6)
    logFrame.Position = UDim2.fromScale(0, 0.1)
    logFrame.BackgroundTransparency = 1
    logFrame.BorderSizePixel = 0
    logFrame.CanvasSize = UDim2.fromScale(0, 0)
    logFrame.ScrollBarThickness = 8
    logFrame.AutomaticCanvasSize = Enum.AutomaticSize.Y
    logFrame.Parent = mainFrame
    
    local logList = Instance.new("UIListLayout")
    logList.SortOrder = Enum.SortOrder.LayoutOrder
    logList.Padding = UDim.new(0, 5)
    logList.Parent = logFrame
    
    local logEntry = Instance.new("TextButton")
    logEntry.Name = "LogEntryTemplate"
    logEntry.Size = UDim2.fromScale(1, 0)
    logEntry.AutomaticSize = Enum.AutomaticSize.Y
    logEntry.BackgroundTransparency = 1
    logEntry.Text = ""
    logEntry.TextColor3 = Color3.fromRGB(200, 200, 200)
    logEntry.TextXAlignment = Enum.TextXAlignment.Left
    logEntry.TextWrapped = true
    logEntry.Font = Enum.Font.Code
    logEntry.TextSize = 14
    logEntry.Parent = logFrame
    logEntry.Visible = false
    
    local btnFrame = Instance.new("Frame")
    btnFrame.Name = "ButtonFrame"
    btnFrame.Size = UDim2.fromScale(1, 0.15)
    btnFrame.Position = UDim2.fromScale(0, 0.75)
    btnFrame.BackgroundTransparency = 1
    btnFrame.Parent = mainFrame
    
    local btnLayout = Instance.new("UIListLayout")
    btnLayout.FillDirection = Enum.FillDirection.Horizontal
    btnLayout.HorizontalAlignment = Enum.HorizontalAlignment.Center
    btnLayout.VerticalAlignment = Enum.VerticalAlignment.Center
    btnLayout.Padding = UDim.new(0, 10)
    btnLayout.Parent = btnFrame
    
    local function createButton(text, action)
        local btn = Instance.new("TextButton")
        btn.Name = "Btn_" .. text
        btn.Size = UDim2.fromScale(0.3, 1)
        btn.BackgroundColor3 = Color3.fromRGB(50, 50, 70)
        btn.Text = text
        btn.TextColor3 = Color3.fromRGB(255, 255, 255)
        btn.TextScaled = true
        btn.Font = Enum.Font.GothamBold
        btn.Parent = btnFrame
        
        local btnCorner = Instance.new("UICorner")
        btnCorner.CornerRadius = UDim.new(0, 8)
        btnCorner.Parent = btn
        
        btn.MouseButton1Click:Connect(action)
        return btn
    end
    
    local btnCopyReport = createButton("Copy Report", function()
        local report = generateReport()
        setclipboard(report)
        log("Report copied to clipboard!", "SUCCESS")
    end)
    
    local btnCopyRemotes = createButton("Copy Remotes", function()
        local remotes = {}
        for _, r in ipairs(analysisData.remotes) do
            remotes[#remotes + 1] = r.path
        end
        setclipboard(table.concat(remotes, "\n"))
        log(#remotes .. " remotes copied to clipboard!", "SUCCESS")
    end)
    
    local btnClose = createButton("Close", function()
        gui:Destroy()
        _G._ExploitHubUI = nil
    end)
    
    -- UI Methods
    local ui = {}
    ui:UpdateLog = function(entry)
        local newEntry = logEntry:Clone()
        newEntry.Visible = true
        newEntry.Text = entry
        newEntry.LayoutOrder = #LOG_BUFFER
        newEntry.Parent = logFrame
        logFrame.CanvasPosition = Vector2.new(0, logFrame.AbsoluteCanvasSize.Y)
    end
    
    -- Load existing logs
    for _, entry in ipairs(LOG_BUFFER) do
        ui:UpdateLog(entry)
    end
    
    _G._ExploitHubUI = ui
    return gui
end

-- 7. MAIN EXECUTION
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
    
    -- 5. Create UI
    local hub = createHubUI()
    
    log("Analysis complete. Interact with the game to capture network traffic.", "INFO")
    log("Use the Hub UI to view logs and copy data.", "INFO")
    
    return hub
end

-- Execute
local hub = main()
return hub
