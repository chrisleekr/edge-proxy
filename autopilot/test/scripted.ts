// The runner with the scripted adapter in place of a model, for admin's
// TestAutopilotRunner. Test only: the image never holds it.
// AUTOPILOT_SCRIPT_HEARTBEAT replaces the 60s heartbeat, as 200ms.
import { parseDuration } from '../src/config.ts';
import { main } from '../src/runner.ts';
import { scripted } from './scripted-adapter.ts';

await main({ claude: scripted, openai: scripted }, parseDuration(process.env['AUTOPILOT_SCRIPT_HEARTBEAT'] ?? '60s'));
