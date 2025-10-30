You are initializing a new project. Your goal is to understand what the user wants to build and create a comprehensive ROADMAP.md that you can execute autonomously later.

## Step 1: Gather Requirements

Use the AskUserQuestion tool to ask about the project. Ask thoughtful questions to understand:

**Project Basics:**
- What is this project? (web app, CLI tool, API, library, etc.)
- What problem does it solve?
- What's the tech stack? (or should you recommend one?)

**Scope & Features:**
- What are the core features? (MVP)
- Any specific requirements or constraints?
- What does "done" look like?

**Technical Details:**
- Testing strategy? (unit tests, integration tests, e2e?)
- Any external services/APIs to integrate?
- Deployment target? (local, cloud, containerized?)

## Step 2: Create ROADMAP.md

Based on the answers, create a detailed ROADMAP.md that includes:

1. **Project Overview** - Clear description of what you're building
2. **Tech Stack** - Languages, frameworks, tools
3. **Architecture** - High-level design decisions
4. **Implementation Phases** - Broken into logical milestones
5. **Testing Strategy** - How to verify each phase
6. **Definition of Done** - Clear success criteria

**IMPORTANT:** The roadmap should be detailed enough that another Claude instance can execute it autonomously without asking questions.

## Step 3: Create Initial Structure

Set up any initial files needed:
- Package manifests (package.json, requirements.txt, etc.)
- Config files
- Directory structure
- README.md with setup instructions

## Step 4: Confirm

Show the user the roadmap and initial structure. Ask if they want to modify anything before starting work.

Tell them: "When you're ready, run `/start` to begin autonomous execution."
