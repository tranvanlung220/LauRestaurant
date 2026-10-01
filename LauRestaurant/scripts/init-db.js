const fs = require('fs'), bcrypt = require('bcryptjs');
const db = require('@neondatabase/serverless').neon(process.env.DATABASE_URL);
(async () => {
  for (const s of fs.readFileSync('schema.sql', 'utf8').split(';').map(s => s.trim()).filter(Boolean)) await db.query(s);
  const users = [['admin', 'Quản trị viên', 'admin'], ['phucvu', 'Nhân viên phục vụ', 'waiter'], ['bep', 'Nhân viên bếp', 'kitchen'], ['thungan', 'Nhân viên thu ngân', 'cashier']];
  for (const [u, n, r] of users)
    await db.query('insert into users(username,password_hash,full_name,role) values($1,$2,$3,$4) on conflict(username) do nothing', [u, await bcrypt.hash('123456', 10), n, r]);
  const [{ c }] = await db.query('select count(*)::int c from menu_items');
  if (!c) {
    await db.query("insert into areas(name) values('Tầng 1'),('Tầng 2')");
    await db.query("insert into dining_tables(area_id,name,seats) select a.id, a.name||' - Bàn '||g, 4 from areas a, generate_series(1,4) g");
    await db.query("insert into categories(name) values('Nước lẩu'),('Thịt & hải sản'),('Rau & nấm'),('Đồ uống')");
    await db.query(`insert into menu_items(category_id,name,price,description)
      select c.id,v.n,v.p,v.d from (values
      ('Nước lẩu','Lẩu Thái chua cay',189000,'Nước dùng sả, ớt, lá chanh'),
      ('Nước lẩu','Lẩu nấm thanh đạm',169000,'Nấm các loại, hầm xương'),
      ('Thịt & hải sản','Bò Mỹ thái lát',129000,'Đĩa 250g'),
      ('Thịt & hải sản','Tôm sú tươi',159000,'Đĩa 300g'),
      ('Rau & nấm','Rau lẩu thập cẩm',49000,'Cải, rau muống, xà lách'),
      ('Rau & nấm','Nấm kim châm',39000,'Đĩa lớn'),
      ('Đồ uống','Trà đá',5000,''),('Đồ uống','Bia Hà Nội',20000,'Lon 330ml')) v(cat,n,p,d)
      join categories c on c.name=v.cat`);
    await db.query("insert into ingredients(name,unit,quantity,min_quantity) values('Thịt bò','kg',20,5),('Tôm sú','kg',10,3),('Nấm kim châm','kg',8,2)");
  }
  console.log('Khởi tạo xong. Tài khoản: admin / 123456 (và phucvu, bep, thungan cùng mật khẩu 123456)');
})().catch(e => { console.error(e); process.exit(1); });
