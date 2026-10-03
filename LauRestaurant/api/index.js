const path = require('path');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { neon } = require('@neondatabase/serverless');

const db = neon(process.env.DATABASE_URL);
const Q = (text, params = []) => db.query(text, params);
const SECRET = process.env.JWT_SECRET || 'dev-secret';

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, '../public'))); // chỉ dùng khi chạy local

const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: e.message }); });
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });

// Xác thực + phân quyền (admin được phép mọi thứ)
const auth = (...roles) => (req, res, next) => {
  try {
    const u = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    if (roles.length && u.role !== 'admin' && !roles.includes(u.role)) return bad(res, 'Bạn không có quyền', 403);
    req.user = u; next();
  } catch { bad(res, 'Vui lòng đăng nhập', 401); }
};

// CRUD dùng chung. read: mảng vai trò | 'public' | null (tự viết GET)
function crud(p, table, cols, read, write, list) {
  list = list || `select * from ${table} order by id`;
  if (read) app.get(`/api/${p}`, ...(read === 'public' ? [] : [auth(...read)]), wrap(async (req, res) => res.json(await Q(list))));
  app.post(`/api/${p}`, auth(...write), wrap(async (req, res) => {
    const [r] = await Q(`insert into ${table}(${cols}) values(${cols.map((_, i) => '$' + (i + 1))}) returning *`, cols.map(c => req.body[c] ?? null));
    res.status(201).json(r);
  }));
  app.put(`/api/${p}/:id`, auth(...write), wrap(async (req, res) => {
    const set = cols.map((c, i) => `${c}=coalesce($${i + 1},${c})`).join(',');
    const [r] = await Q(`update ${table} set ${set} where id=$${cols.length + 1} returning *`, [...cols.map(c => req.body[c] ?? null), req.params.id]);
    r ? res.json(r) : bad(res, 'Không tìm thấy', 404);
  }));
  app.delete(`/api/${p}/:id`, auth(...write), wrap(async (req, res) => { await Q(`delete from ${table} where id=$1`, [req.params.id]); res.json({ ok: true }); }));
}

// ---------- PB01: Đăng nhập ----------
app.post('/api/auth/login', wrap(async (req, res) => {
  const { username, password } = req.body;
  const [u] = await Q('select * from users where username=$1', [username]);
  if (!u || !(await bcrypt.compare(password || '', u.password_hash))) return bad(res, 'Sai tên đăng nhập hoặc mật khẩu', 401);
  const token = jwt.sign({ id: u.id, role: u.role, name: u.full_name }, SECRET, { expiresIn: '12h' });
  res.json({ token, user: { id: u.id, name: u.full_name, role: u.role } });
}));

// ---------- PB02, PB03: Tài khoản & quản lý người dùng ----------
app.get('/api/users', auth('admin'), wrap(async (req, res) => res.json(await Q('select id,username,full_name,role from users order by id'))));
app.post('/api/users', auth('admin'), wrap(async (req, res) => {
  const { username, password, full_name, role } = req.body;
  if (!username || !password || !full_name || !role) return bad(res, 'Vui lòng nhập đủ thông tin');
  const [u] = await Q('insert into users(username,password_hash,full_name,role) values($1,$2,$3,$4) returning id,username,full_name,role', [username, await bcrypt.hash(password, 10), full_name, role]);
  res.status(201).json(u);
}));
app.put('/api/users/:id', auth('admin'), wrap(async (req, res) => {
  const { username, password, full_name, role } = req.body;
  const [u] = await Q('update users set username=coalesce($1,username), full_name=coalesce($2,full_name), role=coalesce($3,role), password_hash=coalesce($4,password_hash) where id=$5 returning id,username,full_name,role',
    [username || null, full_name || null, role || null, password ? await bcrypt.hash(password, 10) : null, req.params.id]);
  res.json(u);
}));
app.delete('/api/users/:id', auth('admin'), wrap(async (req, res) => {
  if (+req.params.id === req.user.id) return bad(res, 'Không thể xóa chính tài khoản đang đăng nhập');
  await Q('delete from users where id=$1', [req.params.id]); res.json({ ok: true });
}));

// ---------- PB04: Khu vực & bàn ----------
crud('areas', 'areas', ['name'], [], ['admin']);
crud('tables', 'dining_tables', ['area_id', 'name', 'seats'], [], ['admin'],
  'select t.*, a.name area from dining_tables t left join areas a on a.id=t.area_id order by t.name');
app.put('/api/tables/:id/status', auth('waiter', 'cashier'), wrap(async (req, res) => {
  const { status } = req.body;
  if (!['empty', 'occupied', 'reserved', 'cleaning'].includes(status)) return bad(res, 'Trạng thái không hợp lệ');
  res.json((await Q('update dining_tables set status=$1 where id=$2 returning *', [status, req.params.id]))[0]);
}));

// ---------- PB05, PB06: Thực đơn, tìm kiếm & lọc món ----------
crud('categories', 'categories', ['name'], 'public', ['admin'], 'select * from categories order by id');
crud('menu', 'menu_items', ['category_id', 'name', 'price', 'description', 'available', 'image'], null, ['admin']);
app.get('/api/menu', wrap(async (req, res) => {
  const { q = '', category = '' } = req.query;
  res.json(await Q(`select m.id,m.category_id,m.name,m.price,m.description,m.available,m.image,
    (m.image_data is not null) has_img, coalesce(length(m.image_data),0) img_v, c.name category_name
    from menu_items m left join categories c on c.id=m.category_id
    where m.name ilike $1 and ($2::text='' or m.category_id::text=$2::text) order by m.category_id, m.name`, [`%${q}%`, category]));
}));
// Ảnh món ăn lưu trong Neon (Vercel không cho ghi file)
app.get('/api/menu/:id/image', wrap(async (req, res) => {
  const [r] = await Q('select image_data from menu_items where id=$1', [req.params.id]);
  const m = r && r.image_data && /^data:(image\/\w+);base64,(.+)$/.exec(r.image_data);
  if (!m) return res.status(404).end();
  res.set({ 'Content-Type': m[1], 'Cache-Control': 'public, max-age=31536000, immutable' }).send(Buffer.from(m[2], 'base64'));
}));
app.put('/api/menu/:id/image', auth('admin'), wrap(async (req, res) => {
  const d = String(req.body.data || '');
  if (!/^data:image\/(jpeg|png|webp);base64,/.test(d) || d.length > 1.5e6) return bad(res, 'Ảnh không hợp lệ hoặc quá lớn');
  await Q('update menu_items set image_data=$1 where id=$2', [d, req.params.id]);
  res.json({ ok: true });
}));
// Bếp bật/tắt "Hết món"
app.put('/api/menu/:id/availability', auth('kitchen'), wrap(async (req, res) =>
  res.json((await Q('update menu_items set available=$1 where id=$2 returning *', [!!req.body.available, req.params.id]))[0])));

// ---------- PB14: Kho nguyên vật liệu ----------
crud('ingredients', 'ingredients', ['name', 'unit', 'quantity', 'min_quantity'], ['kitchen'], ['admin'],
  'select * from ingredients order by (quantity<=min_quantity) desc, name');
app.post('/api/ingredients/:id/receipt', auth('admin'), wrap(async (req, res) => {
  const qty = Number(req.body.quantity);
  if (!(qty > 0)) return bad(res, 'Số lượng phải lớn hơn 0');
  const [r] = await Q(`with r as (insert into stock_receipts(ingredient_id,quantity,note,created_by) values($1,$2::numeric,$3,$4))
    update ingredients set quantity=quantity+$2::numeric where id=$1 returning *`, [req.params.id, qty, req.body.note || null, req.user.id]);
  res.json(r);
}));

// ---------- PB07: Mở bàn & order ----------
app.post('/api/orders', auth('waiter'), wrap(async (req, res) => {
  const [t] = await Q('select status from dining_tables where id=$1', [req.body.table_id]);
  if (!t || ['occupied', 'cleaning'].includes(t.status)) return bad(res, 'Bàn này chưa thể mở');
  const [o] = await Q('insert into orders(table_id,created_by) values($1,$2) returning *', [req.body.table_id, req.user.id]);
  await Q("update dining_tables set status='occupied' where id=$1", [req.body.table_id]);
  res.status(201).json(o);
}));
app.get('/api/orders/open', auth('waiter', 'cashier'), wrap(async (req, res) => res.json(await Q(`
  select o.id, o.table_id, t.name table_name,
    (select count(*) from order_items i where i.order_id=o.id and i.status='done')::int ready,
    (select coalesce(sum(price*quantity),0) from order_items i where i.order_id=o.id)::int total
  from orders o join dining_tables t on t.id=o.table_id where o.status='open' order by o.created_at`))));
app.get('/api/orders/:id', auth('waiter', 'cashier'), wrap(async (req, res) => {
  const [o] = await Q('select o.*, t.name table_name from orders o join dining_tables t on t.id=o.table_id where o.id=$1', [req.params.id]);
  if (!o) return bad(res, 'Không tìm thấy order', 404);
  o.items = await Q('select * from order_items where order_id=$1 order by id', [o.id]);
  o.total = o.items.reduce((s, i) => s + i.price * i.quantity, 0);
  res.json(o);
}));
app.post('/api/orders/:id/items', auth('waiter'), wrap(async (req, res) => {
  const { menu_item_id, quantity = 1, note = '' } = req.body;
  const rows = await Q(`insert into order_items(order_id,menu_item_id,name,price,quantity,note)
    select $1,id,name,price,$3::int,$4 from menu_items where id=$2 and available returning *`, [req.params.id, menu_item_id, quantity, note]);
  rows.length ? res.status(201).json(rows[0]) : bad(res, 'Món này đã hết');
}));
app.delete('/api/orders/:id', auth('waiter'), wrap(async (req, res) => { // hủy order chưa có món
  const [{ n }] = await Q('select count(*)::int n from order_items where order_id=$1', [req.params.id]);
  if (n) return bad(res, 'Order đã có món, không thể hủy');
  const [o] = await Q("delete from orders where id=$1 and status='open' returning table_id", [req.params.id]);
  if (o) await Q("update dining_tables set status='empty' where id=$1", [o.table_id]);
  res.json({ ok: true });
}));

// ---------- PB08: Bếp ----------
app.get('/api/kitchen', auth('kitchen'), wrap(async (req, res) => res.json(await Q(`
  select i.*, t.name table_name from order_items i join orders o on o.id=i.order_id join dining_tables t on t.id=o.table_id
  where i.status in ('pending','cooking') and o.status='open' order by i.created_at`))));
app.put('/api/order-items/:id/status', auth('kitchen', 'waiter'), wrap(async (req, res) => {
  if (!['pending', 'cooking', 'done', 'served'].includes(req.body.status)) return bad(res, 'Trạng thái không hợp lệ');
  res.json((await Q('update order_items set status=$1 where id=$2 returning *', [req.body.status, req.params.id]))[0]);
}));

// ---------- PB09, PB10: Hóa đơn, thanh toán & đóng bàn ----------
app.post('/api/orders/:id/pay', auth('cashier'), wrap(async (req, res) => {
  const [o] = await Q("select * from orders where id=$1 and status='open'", [req.params.id]);
  if (!o) return bad(res, 'Order không còn mở');
  const [{ total }] = await Q('select coalesce(sum(price*quantity),0)::int total from order_items where order_id=$1', [o.id]);
  if (!total) return bad(res, 'Order chưa có món nào');
  const code = 'HD' + Date.now().toString().slice(-8);
  const [inv] = await Q('insert into invoices(code,order_id,total,method) values($1,$2,$3,$4) returning *', [code, o.id, total, req.body.method === 'transfer' ? 'transfer' : 'cash']);
  await Q("update orders set status='paid' where id=$1", [o.id]);
  await Q("update dining_tables set status='cleaning' where id=$1", [o.table_id]); // phục vụ dọn xong → bàn trống
  res.json(inv);
}));

// ---------- PB11: Lịch sử hóa đơn ----------
app.get('/api/invoices', auth('cashier'), wrap(async (req, res) => {
  const { date = '', code = '' } = req.query;
  res.json(await Q(`select i.*, t.name table_name from invoices i join orders o on o.id=i.order_id join dining_tables t on t.id=o.table_id
    where i.code ilike $1 and ($2::text='' or (i.paid_at at time zone 'Asia/Ho_Chi_Minh')::date::text=$2::text) order by i.paid_at desc limit 200`, [`%${code}%`, date]));
}));

// ---------- PB12: Báo cáo doanh thu ----------
app.get('/api/reports', auth('admin'), wrap(async (req, res) => {
  const date = req.query.date || new Date().toLocaleDateString('sv', { timeZone: 'Asia/Ho_Chi_Minh' });
  const day = "(i.paid_at at time zone 'Asia/Ho_Chi_Minh')::date = $1::date";
  const [s] = await Q(`select coalesce(sum(total),0)::int revenue, count(*)::int orders from invoices i where ${day}`, [date]);
  const top = await Q(`select oi.name, sum(oi.quantity)::int qty from order_items oi join invoices i on i.order_id=oi.order_id where ${day} group by oi.name order by qty desc limit 5`, [date]);
  res.json({ date, revenue: s.revenue, orders: s.orders, tables_served: s.orders, top });
}));

// ---------- PB13: Đặt bàn trước (lưu thông tin khách hàng) ----------
app.get('/api/reservations', auth('waiter'), wrap(async (req, res) => res.json(await Q(
  `select r.*, t.name table_name from reservations r left join dining_tables t on t.id=r.table_id order by r.reserved_at desc limit 100`))));
app.post('/api/reservations', auth('waiter'), wrap(async (req, res) => {
  const { table_id, customer_name, phone, party_size, reserved_at, deposit } = req.body;
  if (!customer_name || !phone || !reserved_at) return bad(res, 'Cần tên, số điện thoại và thời gian đặt');
  const [r] = await Q('insert into reservations(table_id,customer_name,phone,party_size,reserved_at,deposit) values($1,$2,$3,$4,$5,$6) returning *',
    [table_id || null, customer_name, phone, party_size || 2, reserved_at, deposit || 0]);
  if (table_id) await Q("update dining_tables set status='reserved' where id=$1", [table_id]);
  res.status(201).json(r);
}));
app.put('/api/reservations/:id/status', auth('waiter'), wrap(async (req, res) => {
  const [r] = await Q('update reservations set status=$1 where id=$2 returning *', [req.body.status, req.params.id]);
  if (r && r.table_id) await Q("update dining_tables set status='empty' where id=$1 and status='reserved'", [r.table_id]); // khách đến/hủy → mở bàn được
  res.json(r);
}));

// Khách đặt bàn trực tiếp từ website (không cần đăng nhập)
app.post('/api/book', wrap(async (req, res) => {
  const { customer_name, phone, party_size, reserved_at } = req.body;
  const name = String(customer_name || '').trim().slice(0, 80), ph = String(phone || '').replace(/[\s.-]/g, '');
  if (!name || !/^\+?\d{9,12}$/.test(ph)) return bad(res, 'Vui lòng nhập họ tên và số điện thoại hợp lệ');
  const when = new Date(reserved_at);
  if (isNaN(when) || when < new Date()) return bad(res, 'Thời gian đặt bàn phải ở tương lai');
  const [{ n }] = await Q("select count(*)::int n from reservations where phone=$1 and created_at > now() - interval '1 hour'", [ph]);
  if (n >= 3) return bad(res, 'Bạn đã gửi quá nhiều yêu cầu, vui lòng gọi trực tiếp cho nhà hàng');
  await Q('insert into reservations(customer_name,phone,party_size,reserved_at,note) values($1,$2,$3,$4,$5)', [name, ph, Math.min(Math.max(+party_size || 2, 1), 50), when.toISOString(), String(req.body.note || '').slice(0, 300)]);
  res.status(201).json({ ok: true });
}));

module.exports = app;
if (require.main === module) app.listen(3000, () => console.log('LauRestaurant chạy tại http://localhost:3000'));
