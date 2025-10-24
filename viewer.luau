
local Class = loadstring(game:HttpGet("https://raw.githubusercontent.com/wirlypirly12/luau-utility/refs/heads/main/class.luau"))()
local GCView = Class.new{
    dependencies = {
        "iscclosure",
        "isexecutorclosure",
        "getinfo",
        "getgc",
        "cloneref",
        "getconstants"
    },
    name = "GCView"
}

function GCView.new(name: string?)
    local self = GCView:create(name)
    self.closures = self:Collect()

    self._running = false
    self._paused = false
    self._refreshint = 300 -- 5 minutes

    return self
end

function GCView:Start()
    if self._running then
        self:log("Already started")
        return
    end

    self._running = true
    self._paused = false

    self:log("Started")

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
        self:log("Not running")
        return
    end

    self._running = false
    self._paused = false
    self.closures = nil

    if self._thread then
        task.cancel(self._thread)
        self._thread = nil
        self:log("Closed update thread")
    end


    self:log("Ended")
end

function GCView:Pause()
    if not self._running then
        self:log("Not running")
        return
    end

    if self._paused then
        self:log("Already paused")
        return
    end

    self._paused = true
    self:log("Paused")
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
            error("issue collecting closures: "..info, 2)
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

    self:log(("Collected %d closures"):format(tostring(num)))
    return collected
end

function GCView:SanatizeParameters(params)
    self:log("Sanatize begin")

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
            params[index] = nil
            continue
        end

        -- check for type mismatch
        local allowed_types = typeof(expt.expected) == "table" and expt.expected or {expt.expected}

        if not table.find(allowed_types, typeof(value)) then
            local reason = #allowed_types > 1 and "multi type mismatch" or "single type mismatch"
            params[index] = nil
            continue
        end
    end

    for index, expt in next, expected do
        if expt.required and params[index] == nil then
            self:Error("missing required:", index)
        end
    end
    self:log("Sanatize end")
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
--     line = 220,
--     script = getfenv().script
-- }
-- Target()

return GCView
