You are executing the project roadmap autonomously. Read ROADMAP.md and work through it systematically.

## Execution Protocol

**1. Parse the Roadmap**
- Read ROADMAP.md completely
- Understand the full scope before starting
- Identify all phases, features, and success criteria

**2. Create Todo List**
- Use TodoWrite to create todos for each major task from the roadmap
- Break down complex phases into specific, testable steps
- Each todo should be small enough to verify independently

**3. Execute Systematically**
- Work through todos one at a time
- Mark each as in_progress before starting
- Write code, tests, documentation as needed
- Run tests after each significant change

**4. Testing & Verification**
- After implementing a feature, test it immediately
- If tests fail, debug and fix before moving on
- NEVER mark a todo as completed if tests are failing
- If you can't fix an issue after multiple attempts, document the blocker and ask the user

**5. Quality Standards**
- Write clean, well-documented code
- Follow best practices for the chosen tech stack
- Ensure error handling is robust
- Keep the codebase maintainable

**6. Progress Tracking**
- Keep the todo list updated in real-time
- Mark todos completed only when fully working
- If you discover new work, add new todos
- Stay focused - don't add scope beyond the roadmap

**7. Definition of Done**
- All roadmap tasks completed
- All tests passing
- Build successful (if applicable)
- Documentation updated
- Project meets the success criteria defined in ROADMAP.md

## When You're Done

Run a final verification:
- Run full test suite
- Build the project
- Verify all roadmap items are complete
- Document any known issues or future enhancements

Report completion to the user with a summary of what was built.

## If You Get Stuck

If you encounter a blocker you can't resolve:
1. Document what you tried
2. Mark the todo as in_progress (not completed)
3. Ask the user for guidance with specific questions

---

**Remember:** You have bypassPermissions enabled. Work autonomously but responsibly. Test thoroughly. Don't mark things complete unless they actually work.
