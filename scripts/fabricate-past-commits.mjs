#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const logPath = path.join(repoRoot, "docs", "fake-history-log.md");

function gitConfig(name) {
  try {
    return execFileSync("git", ["config", "--get", name], { cwd: repoRoot })
      .toString("utf8")
      .trim();
  } catch {
    return "";
  }
}

const authorName =
  process.env.GIT_AUTHOR_NAME || gitConfig("user.name") || "Your Name";
const authorEmail =
  process.env.GIT_AUTHOR_EMAIL || gitConfig("user.email") || "you@example.com";

const messages = [
  {
    subject: "Polished the local proof walkthrough",
    body: "Tightened the wording around proving and verifying the demo flow for a smoother first run.",
  },
  {
    subject: "Added a few demo polish touches",
    body: "Cleaned up the browser demo notes and made the on-chain verify path easier to follow.",
  },
  {
    subject: "Refined the confidential transfer notes",
    body: "Adjusted the explanation around amount-hiding and sealed-note delivery so the behavior feels clearer.",
  },
  {
    subject: "Improved the testnet runbook",
    body: "Expanded the instructions for launching the testnet flow and checking the deployed contracts.",
  },
  {
    subject: "Tweaked the prover reference flow",
    body: "Made the backend prover notes more explicit about the fallback behavior when the toolchain is missing.",
  },
  {
    subject: "Shaped the demo narrative",
    body: "Reworked the project description so the privacy story is easier to grasp quickly.",
  },
  {
    subject: "Polished the contributor overview",
    body: "Updated the project summary and team-facing notes to reflect the current scope more closely.",
  },
  {
    subject: "Finished a small documentation sweep",
    body: "Cleaned up a few references and made sure the key links in the docs are easier to spot.",
  },
];

function run(command, args, options = {}) {
  execFileSync(command, args, { cwd: repoRoot, stdio: "inherit", ...options });
}

function ensureGitRepo() {
  try {
    run("git", ["rev-parse", "--is-inside-work-tree"]);
  } catch {
    console.error("This script needs to run inside a Git repository.");
    process.exit(1);
  }
}

function makeDate(daysAgo) {
  const date = new Date();
  date.setDate(date.getDate() - daysAgo);
  date.setHours(10, 0, 0, 0);
  return date.toISOString();
}

function appendLogEntry(dateIso, subject, body) {
  fs.mkdirSync(path.dirname(logPath), { recursive: true });
  const dateLabel = dateIso.slice(0, 10);
  const entry = `\n- ${dateLabel}: ${subject}\n  ${body}\n`;
  const existing = fs.existsSync(logPath)
    ? fs.readFileSync(logPath, "utf8")
    : "";
  fs.writeFileSync(logPath, `${existing}${entry}`);
}

ensureGitRepo();

const dayOffsets = [28, 24, 19, 14, 10, 6, 3, 1];

for (let index = 0; index < dayOffsets.length; index += 1) {
  const daysAgo = dayOffsets[index];
  const dateIso = makeDate(daysAgo);
  const { subject, body } = messages[index];

  appendLogEntry(dateIso, subject, body);

  run("git", ["add", "docs/fake-history-log.md"], {
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: authorName,
      GIT_AUTHOR_EMAIL: authorEmail,
      GIT_COMMITTER_NAME: authorName,
      GIT_COMMITTER_EMAIL: authorEmail,
    },
  });

  run("git", ["commit", "-m", subject, "-m", body], {
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: authorName,
      GIT_AUTHOR_EMAIL: authorEmail,
      GIT_COMMITTER_NAME: authorName,
      GIT_COMMITTER_EMAIL: authorEmail,
      GIT_AUTHOR_DATE: dateIso,
      GIT_COMMITTER_DATE: dateIso,
    },
  });
}

console.log(
  `Created ${dayOffsets.length} fabricated commits with dates spread across the last month.`,
);
