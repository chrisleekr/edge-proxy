// Replay with the scripted adapter in place of a model, for admin's
// TestAutopilotRunner. Test only: the image never holds it.
import { replayMain } from '../src/replay.ts';
import { scripted } from './scripted-adapter.ts';

await replayMain({ claude: scripted, openai: scripted });
