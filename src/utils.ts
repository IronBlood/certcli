import { setTimeout } from "node:timers/promises";

export async function sleep(delay: number) {
	await setTimeout(delay);
}
