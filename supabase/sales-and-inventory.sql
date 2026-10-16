-- Thrift to Cloud: sales history, automatic inventory deduction, and 10 more stalls.
-- Run once in Supabase Dashboard > SQL Editor. Safe to re-run.

-- 1. Sales history tables -----------------------------------------------------
create table if not exists public.sales (
  id uuid primary key default gen_random_uuid(),
  reference text unique not null default ('TTC-' || to_char(now(), 'YYMMDD') || '-' || substr(md5(random()::text), 1, 5)),
  stall_id uuid not null references public.stalls(id) on delete cascade,
  customer_name text,
  total numeric(12,2) not null default 0,
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now()
);

create table if not exists public.sale_items (
  id uuid primary key default gen_random_uuid(),
  sale_id uuid not null references public.sales(id) on delete cascade,
  product_id uuid references public.products(id) on delete set null,
  product_name text not null,
  unit_price numeric(12,2) not null,
  quantity integer not null check (quantity > 0)
);

create index if not exists sales_stall_created_idx on public.sales (stall_id, created_at desc);
create index if not exists sale_items_sale_idx on public.sale_items (sale_id);

alter table public.sales enable row level security;
alter table public.sale_items enable row level security;

-- Stall members can only read their own stall's sales. Writes go through record_stall_sale().
drop policy if exists "members read own stall sales" on public.sales;
create policy "members read own stall sales" on public.sales for select to authenticated
  using (exists (select 1 from public.stall_memberships m where m.stall_id = sales.stall_id and m.user_id = auth.uid()));

drop policy if exists "members read own stall sale items" on public.sale_items;
create policy "members read own stall sale items" on public.sale_items for select to authenticated
  using (exists (
    select 1 from public.sales s join public.stall_memberships m on m.stall_id = s.stall_id
    where s.id = sale_items.sale_id and m.user_id = auth.uid()
  ));

-- 2. Atomic sale: checks stock, deducts inventory, writes history ---------------
create or replace function public.record_stall_sale(p_stall_id uuid, p_customer_name text, p_items jsonb)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_sale_id uuid;
  v_reference text;
  v_total numeric(12,2) := 0;
  v_item jsonb;
  v_qty integer;
  v_product public.products%rowtype;
begin
  if auth.uid() is null then
    raise exception 'Please log in to record a sale.';
  end if;
  if not exists (select 1 from public.stall_memberships where stall_id = p_stall_id and user_id = auth.uid()) then
    raise exception 'You do not have access to this stall.';
  end if;
  if p_items is null or jsonb_array_length(p_items) = 0 then
    raise exception 'Add at least one item to the sale.';
  end if;

  insert into public.sales (stall_id, customer_name)
  values (p_stall_id, nullif(trim(p_customer_name), ''))
  returning id, reference into v_sale_id, v_reference;

  for v_item in select * from jsonb_array_elements(p_items) loop
    v_qty := (v_item->>'quantity')::integer;
    if v_qty is null or v_qty < 1 or v_qty > 10000 then
      raise exception 'Invalid quantity.';
    end if;

    -- Row lock prevents two sales from selling the same last item.
    select * into v_product from public.products
      where id = (v_item->>'product_id')::uuid and stall_id = p_stall_id
      for update;
    if not found then
      raise exception 'A product in this sale no longer exists.';
    end if;
    if v_product.quantity < v_qty then
      raise exception '%: only % left in stock.', v_product.name, v_product.quantity;
    end if;

    update public.products set quantity = quantity - v_qty where id = v_product.id;

    insert into public.sale_items (sale_id, product_id, product_name, unit_price, quantity)
    values (v_sale_id, v_product.id, v_product.name, v_product.price, v_qty);

    v_total := v_total + v_product.price * v_qty;
  end loop;

  update public.sales set total = v_total where id = v_sale_id;
  return v_reference;
end;
$$;

revoke all on function public.record_stall_sale(uuid, text, jsonb) from public, anon;
grant execute on function public.record_stall_sale(uuid, text, jsonb) to authenticated;

-- Never allow negative stock, whatever path updates it.
do $$ begin
  alter table public.products add constraint products_quantity_nonnegative check (quantity >= 0);
exception when duplicate_object then null; end $$;

-- 3. Buyers can see the list of open stalls ------------------------------------
drop policy if exists "public read active stalls" on public.stalls;
create policy "public read active stalls" on public.stalls for select to anon, authenticated
  using (is_active = true);

-- 4. Ten more stalls ------------------------------------------------------------
insert into public.stalls (name, stall_no, location, is_active)
select v.name, v.stall_no, v.location, true
from (values
  ('Pine Hill Ukay',        '02', 'Harrison Road, Baguio City'),
  ('Session Road Vintage',  '03', 'Session Road, Baguio City'),
  ('Burnham Thrift Corner', '04', 'Burnham Park, Baguio City'),
  ('Cloudline Denim',       '05', 'Harrison Road, Baguio City'),
  ('Mines View Finds',      '06', 'Mines View, Baguio City'),
  ('Strawberry Fields Wear','07', 'La Trinidad, Benguet'),
  ('Camp John Hay Closet',  '08', 'Loakan Road, Baguio City'),
  ('Kalye Retro Shop',      '09', 'Magsaysay Ave, Baguio City'),
  ('Highland Jackets',      '10', 'Night Market, Baguio City'),
  ('Sunrise Second Hand',   '11', 'Legarda Road, Baguio City')
) as v(name, stall_no, location)
where not exists (select 1 from public.stalls s where s.stall_no = v.stall_no);

-- 5. Staff roles: admin, operator, stall_owner ----------------------------------
do $$
declare c record;
begin
  for c in select conname from pg_constraint
    where conrelid = 'public.stall_memberships'::regclass and contype = 'c'
      and pg_get_constraintdef(oid) ilike '%member_role%'
  loop
    execute format('alter table public.stall_memberships drop constraint %I', c.conname);
  end loop;
  alter table public.stall_memberships add constraint stall_memberships_member_role_check
    check (member_role in ('admin', 'operator', 'stall_owner'));
end $$;

-- To give someone a role, run (replace the email, role and stall number):
-- insert into public.stall_memberships (user_id, stall_id, member_role)
-- select u.id, s.id, 'operator' from auth.users u, public.stalls s
-- where u.email = 'person@example.com' and s.stall_no = '02';
