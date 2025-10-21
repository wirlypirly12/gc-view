local dependencies = {
    "iscclosure",
    "isexecutorclosure",
    "getinfo",
    "getgc",
    "cloneref",
    "getconstants"
}

for i, depend in next, dependencies do
    local func = getgenv()[depend]
    assert(func, "\n"..depend.. " is not supported by "..identifyexecutor().."\nplease use a different exploit if you'd like to use gcview")
end

local Services; Services = setmetatable({}, {__index = function(self, key)
    if self == Services then
        local service = cloneref(game:GetService(key))
        rawset(self, key, service)
        return service
    end
end})

local Class = {}
Class.__index = Class

function Class:Log(func, msg)
    for i, v in ipairs(msg) do
        msg[i] = tostring(v)
    end
    msg = table.concat(msg, " ")
    if func == error then
        error(msg, 3)
    else
        func(msg)
    end
end

function Class:Proxy(f, msg, self)
    return Class:Log(f, {"[" .. tostring(self) .. "] ~", table.unpack(msg)})
end

function Class.new(module)
    local mt = getmetatable(module) or {}
    local self = setmetatable({}, {__index = module, __tostring = mt.__tostring})

    function self:Log(...)
        return Class:Proxy(warn, {...}, self)
    end

    function self:Error(...)
        return Class:Proxy(error, {...}, self)
    end

    return self
end

local GCView = setmetatable({}, {__tostring = function() return "GCView" end})

function GCView.new()
    local self = Class.new(GCView)
    self.closures = self:Collect()

    self._running = false
    self._paused = false
    self._refreshint = 300 -- 5 minutes

    return self
end

function GCView:Start()
    if self._running then
        self:Log("Already started")
        return
    end

    self._running = true
    self._paused = false

    self:Log("Started")

    self._thread = task.spawn(function()
        while true do
            if not self._paused and self._running then
                self.closures = self:Collect()
            end
            task.wait(self._refreshint)
        end
    end)
end

function GCView:End()
    if not self._running then
        self:Log("Not running")
        return
    end

    self._running = false
    self._paused = false
    self.closures = nil

    if self._thread then
        task.cancel(self._thread)
        self._thread = nil
        self:Log("Closed update thread")
    end


    self:Log("Ended")
end

function GCView:Pause()
    if not self._running then
        self:Log("Not running")
        return
    end

    if self._paused then
        self:Log("Already paused")
        return
    end

    self._paused = true
    self:Log("Paused")
end

function GCView:Collect()
    local collected = {}
    local num = 0

    for i, closure in next, getgc() do

        -- skip over c functions & executor functions
        if iscclosure(closure) then
            continue
        end

        local success, info = pcall(getinfo, closure)

        if not success then
            self:Error("error while collecting closures:", info)
        end

        -- split Path.To.Source into {Path, To, Source}
        local script_names = string.split(info.source, ".")
        local name = script_names[#script_names]

        local captured_consts, consts = pcall(getconstants, closure)
        local captured_fenv, fenv = pcall(getfenv, closure)

        collected[closure] = {
            owner = name,
            name = info.name,
            linedefined = info.linedefined or info.currentline,
            source = info.source,
            nups = info.nups,
            nconsts = captured_consts and #consts,
            _script = captured_fenv and fenv.script
        }
        num += 1
    end

    self:Log(("Collected %d closures"):format(tostring(num)))
    return collected
end

function GCView:SanatizeParameters(params)
    self:Log("Sanatize begin")

    local function RemoveIndex(index, reason)
        self:Log("Removed", index, "from params ("..tostring(reason)..")")
        params[index] = nil
    end

    local expected = {
        script = {required = false, expected = {"Instance", "string"}},
        nups = {required = false, expected = "number"},
        nconsts = {required = false, expected = "number"},
        line = {required = false, expected = "number"},
        source = {required = false, expected = "string"},
        name = {required = false, expected = "string"},
        multi = {required = false, expected = "boolean"}
    }

    for index, value in next, params do
        local expt = expected[index]

        -- remove unexpected params
        if expt == nil then
            RemoveIndex(index, "not expected")
            continue
        end

        -- check for type mismatch
        local allowed_types = typeof(expt.expected) == "table" and expt.expected or {expt.expected}

        if not table.find(allowed_types, typeof(value)) then
            local reason = #allowed_types > 1 and "multi type mismatch" or "single type mismatch"
            RemoveIndex(index, reason)
            continue
        end
    end

    for index, expt in next, expected do
        if expt.required and params[index] == nil then
            self:Error("missing required:", index)
        end
    end
    self:Log("Sanatize end")
    return params
end

function GCView:Evaluate(info, params)
    local keymap = {
        script = "_script",
        line = "linedefined",
        name = "name",
        source = "source",
        nups = "nups",
        nconsts = "nconsts"
    }


    for pkey, pval in next, params do
        if pkey == "multi" then
            continue
        end

        local ikey = keymap[pkey] or pkey
        local ival = info[ikey]

        if ival == nil then
            return false
        end

        if pkey == "script" then
            if typeof(pval) == "Instance" then
                if ival ~= pval then return false end
            else
                local ownername = info.owner or (typeof(ival) == "Instance" and ival.Name)
                if ownername ~= pval then return false end
            end
        elseif pkey == "line" or pkey == "nups" or pkey == "nconsts" then
            if tonumber(pval) ~= tonumber(ival) then return false end
        else
            if tostring(ival) ~= tostring(pval) then return false end
        end
    end

    return true
end

function GCView:Scan(params)
    assert(self.closures, "closures not found")

    params = self:SanatizeParameters(params)
    local found_closures = {}

    for closure, closureinfo in next, self.closures do
        if self:Evaluate(closureinfo, params) then
            found_closures[#found_closures+1] = closure
        end
    end

    return params.multi and found_closures or found_closures[1]
end


-- example:
-- function FindMeOrDont()
--     print("Yo")
-- end

-- local Viewer = GCView.new()
-- local Target = Viewer:Scan{
--     name = "FindMeOrDont",
--     nconsts = 1,
--     nups = 0,
--     line = 270,
--     script = getfenv().script
-- }
-- Target()

return GCView
