create table if not exists public.gdelt_cleaner_results (
    event_id text primary key,
    article_url text not null,
    review_status text not null check (review_status in (
        'kept', 'discarded', 'inaccessible', 'model_error',
        'review_location', 'review_relevance'
    )),
    gdelt_location text,
    latitude double precision,
    longitude double precision,
    retry_after timestamptz,
    updated_at timestamptz not null default now(),
    payload jsonb not null
);

alter table public.gdelt_cleaner_results enable row level security;
revoke all on public.gdelt_cleaner_results from anon, authenticated;
grant select, insert, update on public.gdelt_cleaner_results to service_role;

create or replace function public.preserve_terminal_gdelt_result()
returns trigger language plpgsql set search_path = '' as $$
begin
    if old.review_status in ('kept', 'discarded')
       and new.review_status not in ('kept', 'discarded') then
        return null;
    end if;
    return new;
end;
$$;

drop trigger if exists preserve_terminal_gdelt_result on public.gdelt_cleaner_results;
create trigger preserve_terminal_gdelt_result
before update on public.gdelt_cleaner_results
for each row execute function public.preserve_terminal_gdelt_result();
