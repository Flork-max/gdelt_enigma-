# gdelt_enigma-
Fetchs gdelt event data and cleans it via LLM

# GDELT cleaner

The cleaner uses GDELT URLs to find candidate articles about political violence or armed conflict in Pakistan. It excludes routine crime and unrelated news. For an article with a supported location and one gazetteer match, it replaces the location and coordinates and preserves the originals. The GDELT date and event code remain source metadata. A corrected row is still an article-derived report.

## Run on Windows

Unzip the package into your cleaner folder or copy your existing `events.json` and `gazetteer.csv` beside the script. Use Python 3.11 or newer.

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:GROQ_API_KEY = Read-Host "Groq API key"
$env:OPENROUTER_API_KEY = Read-Host "OpenRouter API key"
$env:MODEL_CHAIN = "groq:qwen/qwen3.8-27b,groq:openai/gpt-oss-20b,openrouter:openrouter/free"
.\.venv\Scripts\python.exe clean_gdelt.py events.json --gazetteer gazetteer.csv --limit 15
```

Supply a key for at least one configured provider. For Gemini add `,gemini:gemini-3.1-flash-lite` to the chain and set `GEMINI_API_KEY`. For paid DeepSeek add `,deepseek:deepseek-flash` and set `DEEPSEEK_API_KEY`. Provider availability and free quotas depend on your account. Keep API keys in your environment or scheduler secrets.

The gazetteer CSV requires `name,latitude,longitude`. An optional `aliases` column uses pipes between alternative spellings. Keep city and district reference points distinct. Unmatched or ambiguous names go to review.

The script retries transient provider errors once with a short delay. It switches models after persistent provider errors, rate limits, or invalid responses. It records the provider and returned model ID for usable responses. Exhausting the model chain produces a review row with `model_error`.

## Save in Supabase

Run `supabase.sql` in your project's SQL Editor. It creates the table `gdelt_cleaner_results`. Configure the project URL and a server-side secret key.

```powershell
$env:SUPABASE_URL = "https://YOUR-PROJECT.supabase.co"
$env:SUPABASE_KEY = Read-Host "Supabase server-side secret key"
.\.venv\Scripts\python.exe clean_gdelt.py events.json --gazetteer gazetteer.csv --limit 15 --save-supabase
```

Filter the table by `review_status = 'kept'` for cleaned rows. Other rows carry their status and details in `payload`. Writes upsert by GDELT event ID. Runs skip earlier kept and discarded records and respect retry timestamps for pending rows. Model failures are eligible again after 15 minutes. Other review or access failures are eligible after six hours. A write error leaves the CSV row available for inspection and sets the program exit code to 1.

## Fetch new rows automatically

Authenticate the account running the script with BigQuery Application Default Credentials. For a local trial with the Google Cloud CLI, run `gcloud auth application-default login`. Use a Google Cloud project allowed to run BigQuery jobs. For an unattended runner, configure its service identity or workload identity.

```powershell
.\.venv\Scripts\python.exe clean_gdelt.py --bigquery-project YOUR-GCP-PROJECT --gazetteer gazetteer.csv --limit 50 --lookback-days 3 --save-supabase
```

Schedule that command in Windows Task Scheduler or your existing runner. Set the working directory to the project folder and make the credentials available to the account that runs the job. Run one instance at a time. The BigQuery command reads UTC partitions for Pakistan with root codes 18 to 20, then takes up to the configured number of eligible rows. It caps each query at 2 GB by default. `--max-bytes-billed` sets the cap in bytes.

The rolling window includes today. Rows older than the window can be retried by widening `--lookback-days` or rerunning their JSON export. Check whether the number processed per day keeps up with incoming rows before relying on a schedule. Free-tier endpoints can exhaust their quotas. CSVs reflect the latest run with eligible rows and are overwritten on the next such run.
