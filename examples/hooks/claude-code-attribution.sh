#!/bin/sh
# Claude Code hook: attribute the cr commands Claude runs to the session,
# prompt, and permission mode Claude Code reports, without asking the model to
# declare any of it. Installation, and the reasoning behind each choice, are in
# docs/agents.md under "Let Claude Code fill in the attribution".
#
# As a PreToolUse hook. A PreToolUse hook cannot set environment variables for
# the command it precedes, but it can replace the tool's input through
# hookSpecificOutput.updatedInput. So for a Bash command that runs cr, this
# prints the same input with one line in front of the command:
#
#   export CR_HOOK_AGENT='{"id":"claude-code",...}' CR_HOOK_AUTHORIZATION='{...}'
#
# As a SessionStart hook. SessionStart can export variables to every later Bash
# command by appending to $CLAUDE_ENV_FILE, but it runs when a session starts,
# not for each call, so it cannot know a call's prompt or permission mode. This
# appends the agent and the session alone, so a cr the PreToolUse filter does
# not recognise is still tied to its session.
#
# cr records both variables with detected_from "hook", beneath anything
# declared with a flag or CR_AGENT: the hook never overrides a declaration and
# never takes credit for one.
#
# The hook makes no permission decision and never blocks. Without jq, for any
# other command, or on input it cannot read, it does nothing and exits 0, which
# leaves the command exactly as Claude wrote it.
#
# Needs a POSIX shell and jq.

command -v jq >/dev/null 2>&1 || exit 0

common='
  # Claude Code permission_mode -> cr authorization mode. The hook runs before
  # the permission check, so it never knows whether a person approved this
  # particular call and never claims "interactive". Where a prompt was possible
  # (default, acceptEdits, plan) the answer is "unknown". Where nothing was
  # going to ask (auto, dontAsk, bypassPermissions) a standing grant covered
  # the call: "delegated". The raw value is kept as the grant.
  def approval:
    if . == "auto" or . == "dontAsk" or . == "bypassPermissions" then "delegated"
    else "unknown"
    end;

  # Keep a value only if cr would accept it as an identifier, so an odd
  # session or prompt ID drops that one field rather than failing the write.
  def identifier:
    select(type == "string" and length > 0 and length <= 256
           and (test("[[:cntrl:]]") | not));

  def session: {session: (.session_id | identifier)} // {};
  def turn: {turn: (.prompt_id | identifier)} // {};
  def grant: {grant: (.permission_mode | identifier)} // {};
  def assign($name; $value): "\($name)=\($value | tojson | @sh)";
'

pre_tool_use='
  select(.tool_name == "Bash" and (.tool_input | type == "object"))
  | .tool_input as $input
  | select($input.command | type == "string"
           and test("(^|[^[:alnum:]_.-])cr([^[:alnum:]_.-]|$)"))
  | ("export \(assign("CR_HOOK_AGENT"; {id: "claude-code"} + session + turn))"
     + " \(assign("CR_HOOK_AUTHORIZATION"; {mode: (.permission_mode | approval)} + grant))")
    as $export
  | {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        updatedInput: ($input + {command: ($export + "\n" + $input.command)})
      }
    }
'

session_start='
  "export \(assign("CR_HOOK_AGENT"; {id: "claude-code"} + session))"
'

input=$(cat)
event=$(printf '%s' "$input" | jq -r '.hook_event_name | strings' 2>/dev/null)

# jq exits 2 on unreadable input, and exit status 2 is the one a PreToolUse
# hook uses to block a call, so no jq status is ever passed on. Nothing goes to
# stdout for SessionStart either: Claude would read it as conversation context.
case $event in
  PreToolUse)
    printf '%s' "$input" | jq -c "$common $pre_tool_use" 2>/dev/null
    ;;
  SessionStart)
    if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
      printf '%s' "$input" | jq -r "$common $session_start" 2>/dev/null \
        >>"$CLAUDE_ENV_FILE"
    fi
    ;;
esac
exit 0
