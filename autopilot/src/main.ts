import { runClaude } from './claude.ts';
import { runOpenAI } from './openai.ts';
import { main } from './runner.ts';

await main({ claude: runClaude, openai: runOpenAI }, 60_000);
