import readline from "node:readline/promises";
import { stdin, stdout} from "node:process";
import chalk from "chalk";

export async function prompt({
	question,
}: {
	question: string;
}): Promise<string> {
	const rl = readline.createInterface({
		input: stdin,
		output: stdout,
	});

	const answer = await rl.question(question);
	rl.close();

	return answer.trim();
}

export async function prompt_without_output(): Promise<void> {
	const rl = readline.createInterface({ input: stdin });

	await new Promise<void>((resolve) => {
		rl.once("line", () => resolve());
	});

	rl.close();
}

export async function check_pause() {
	const answerTest = await prompt({
		question: `${chalk.cyan("Continue?")} (y/N): `
	});
	if (answerTest.toUpperCase() !== "Y") {
		console.error(chalk.red("Aborted: user did not confirm with 'Y' or 'y'."));
		process.exit(1);
	}
}

export async function accept_term() {
	const ans = await prompt({
		question: `${chalk.cyan("Do you accept the Let's Encrypt terms and conditions?")}\n${chalk.italic.underline("https://letsencrypt.org/documents/LE-SA-v1.5-February-24-2025.pdf")}\n(y/N): `
	});
	if (ans.toUpperCase() !== "Y") {
		console.error(chalk.red("Aborted: user did not accept the Let's Encrypt terms and conditions"));
		process.exit(1);
	}
}
