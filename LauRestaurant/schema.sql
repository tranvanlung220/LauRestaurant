create table if not exists users(id serial primary key, username text unique not null, password_hash text not null, full_name text not null, role text not null check (role in ('admin','waiter','kitchen','cashier')), created_at timestamptz default now());
create table if not exists areas(id serial primary key, name text not null);
create table if not exists dining_tables(id serial primary key, area_id int references areas(id) on delete cascade, name text not null, seats int default 4, status text default 'empty');
create table if not exists categories(id serial primary key, name text not null);
create table if not exists menu_items(id serial primary key, category_id int references categories(id) on delete set null, name text not null, price int not null, description text, available boolean default true);
create table if not exists ingredients(id serial primary key, name text not null, unit text default 'kg', quantity numeric default 0, min_quantity numeric default 0);
create table if not exists stock_receipts(id serial primary key, ingredient_id int references ingredients(id) on delete cascade, quantity numeric not null, note text, created_by int, created_at timestamptz default now());
create table if not exists orders(id serial primary key, table_id int references dining_tables(id), status text default 'open', created_by int, created_at timestamptz default now());
create table if not exists order_items(id serial primary key, order_id int references orders(id) on delete cascade, menu_item_id int, name text, price int, quantity int default 1, note text, status text default 'pending', created_at timestamptz default now());
create table if not exists invoices(id serial primary key, code text unique, order_id int references orders(id), total int, method text, paid_at timestamptz default now());
create table if not exists reservations(id serial primary key, table_id int references dining_tables(id) on delete set null, customer_name text not null, phone text not null, party_size int default 2, reserved_at timestamptz not null, deposit int default 0, status text default 'booked', created_at timestamptz default now());
alter table menu_items add column if not exists image text;
alter table menu_items add column if not exists image_data text;
alter table reservations add column if not exists note text
