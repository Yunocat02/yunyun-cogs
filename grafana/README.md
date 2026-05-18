# Grafana Discord Cog

Cog นี้ใช้สำหรับ Red-DiscordBot เพื่อดึงภาพกราฟจาก Grafana Render API แล้วส่งเป็นรูปภาพใน Discord

เหมาะกับกรณีนี้:

- Grafana อยู่ที่เครื่อง `<grafana-host>`
- Discord bot อยู่คนละเครื่อง แต่สามารถยิง HTTP ไปที่ Grafana ได้
- ต้องการเปลี่ยน Grafana endpoint ได้ด้วย command
- ต้องการเลือก Dashboard / Panel / Variables / Time Range ได้
- ใช้ Grafana Image Renderer แล้ว เช่น container `grafana/grafana-image-renderer:v5.1.0-arm64`

---

## 1) โครงสร้างไฟล์

วางโฟลเดอร์นี้ไว้ใน custom cogs ของ Red-DiscordBot:

```text
grafana/
├── README.md
├── __init__.py
├── info.json
└── grafana.py
```

---

## 2) สิ่งที่ต้องตรวจสอบก่อนใช้งาน

จากเครื่อง Discord Bot ต้องยิงไปหา Grafana ได้ เช่น:

```bash
curl -I http://<grafana-host>:3000
```

หรือถ้า Grafana ใช้ port อื่น ให้เปลี่ยนตามจริง

> จาก `docker ps` ที่ส่งมา container `grafana` ยังไม่เห็น port mapping ใน output ดังนั้นต้องตรวจสอบว่า Grafana expose port 3000 อยู่จริงหรือไม่ เช่นใช้ `docker port grafana` หรือดู compose file

ถ้าใช้ Docker Compose ตัวอย่างควรมีประมาณนี้:

```yaml
ports:
  - "3000:3000"
```

---

## 3) ติดตั้ง Cog

ตัวอย่างสำหรับ Red-DiscordBot:

```bash
[p]load downloader
[p]repo add localgrafana file:///path/to/your/cogs
[p]cog install localgrafana grafana
[p]load grafana
```

ถ้าวางเองใน local cogs path ของ Redbot ให้ใช้วิธีตามที่คุณใช้งานอยู่ได้เลย

---

## 4) ตั้งค่าเริ่มต้น

### 4.1 ตั้ง Grafana endpoint

```text
[p]grafana endpoint http://<grafana-host>:3000
```

ตัวอย่างถ้าใช้ reverse proxy:

```text
[p]grafana endpoint https://grafana.example.com
```

### 4.2 ตั้ง API Token ถ้า Grafana ต้อง login

```text
[p]grafana token glsa_xxxxxxxxxxxxxxxxx
```

ถ้า Grafana เปิด anonymous access หรือ render ได้โดยไม่ต้อง login สามารถไม่ตั้ง token ได้

ลบ token:

```text
[p]grafana token_clear
```

### 4.3 ตั้ง orgId

```text
[p]grafana org 1
```

### 4.4 ตั้ง Timezone

```text
[p]grafana tz Asia/Bangkok
```

---

## 5) เพิ่ม Panel ที่ต้องการเรียกใช้

ใช้ Dashboard UID และ Panel ID จาก Grafana

วิธีดู:
1. เปิด Dashboard ใน Grafana
2. กดที่ Panel
3. Inspect / Share / Link
4. ดูค่า `uid` ของ dashboard และ `panelId`

เพิ่ม panel:

```text
[p]grafana panel_add linux_cpu <dashboard_uid> 1
```

เพิ่มพร้อม slug:

```text
[p]grafana panel_add linux_cpu <dashboard_uid> 1 linux-monitoring
```

ดูรายการ panel:

```text
[p]grafana panel_list
```

ลบ panel:

```text
[p]grafana panel_del linux_cpu
```

---

## 6) เรียกดูกราฟ

### 6.1 เรียกแบบง่าย

```text
[p]grafana graph linux_cpu
```

ค่า default:
- from: `now-6h`
- to: `now`
- width: `1000`
- height: `500`

### 6.2 กำหนด time range

```text
[p]grafana graph linux_cpu from=now-24h to=now
```

```text
[p]grafana graph linux_cpu range=3h
```

`range=3h` จะเท่ากับ `from=now-3h to=now`

### 6.3 กำหนด variables

Grafana variables ต้องส่งเป็น query parameter รูปแบบ `var-ชื่อ=value`

เช่น dashboard มี variable:
- `job`
- `node`
- `nodename`
- `ds_prometheus`

สั่งได้แบบนี้:

```text
[p]grafana graph linux_cpu range=6h var-job=node var-node=<node-exporter-host>:9100
```

หรือใช้ key แบบไม่ต้องใส่ `var-` ก็ได้:

```text
[p]grafana graph linux_cpu range=6h job=node node=<node-exporter-host>:9100
```

Cog จะเติม `var-` ให้เองสำหรับ key ที่ไม่ใช่ option reserved

### 6.4 กำหนดขนาดรูป

```text
[p]grafana graph linux_cpu range=12h width=1400 height=700
```

---

## 7) สั่ง render ด้วย raw UID / Panel ID โดยไม่ต้องบันทึก panel

```text
[p]grafana render <dashboard_uid> <panel_id> from=now-6h to=now var-job=node
```

ตัวอย่าง:

```text
[p]grafana render abc123 4 range=24h var-job=node var-node=<node-exporter-host>:9100
```

---

## 8) ตั้ง Default Variables

ถ้าทุกกราฟใช้ค่า variable เดิมบ่อย ๆ สามารถตั้ง default ได้

```text
[p]grafana defaultvar job node
[p]grafana defaultvar node <node-exporter-host>:9100
[p]grafana defaultvar nodename poko-jetson-nano
```

ดู default variables:

```text
[p]grafana defaultvars
```

ลบ default variable:

```text
[p]grafana defaultvar_del node
```

ตอนเรียก `graph` หรือ `render` สามารถ override ได้ เช่น:

```text
[p]grafana graph linux_cpu range=1h node=<another-node-exporter-host>:9100
```

---

## 9) Health Check

ตรวจสอบว่า bot ติดต่อ Grafana ได้:

```text
[p]grafana ping
```

ตรวจสอบ render endpoint แบบเร็ว:

```text
[p]grafana test linux_cpu
```

---

## 10) ตัวอย่าง Workflow สำหรับ Dashboard Linux-Monitoring

สมมติ Dashboard UID คือ `linux123` และ panel CPU คือ `2`

```text
[p]grafana endpoint http://<grafana-host>:3000
[p]grafana org 1
[p]grafana tz Asia/Bangkok
[p]grafana panel_add cpu linux123 2 linux-monitoring
[p]grafana defaultvar job node
[p]grafana defaultvar node <node-exporter-host>:9100
[p]grafana graph cpu range=6h
```

---

## 11) หมายเหตุเรื่อง `$__rate_interval`

`$__rate_interval` เป็นตัวแปรภายใน Grafana ที่ Grafana คำนวณให้เองตอน render panel โดยอิงจาก datasource scrape interval, panel resolution และ time range

ถ้า Prometheus scrape interval = `3m` แนะนำให้ตั้ง Min step ใน panel หรือ datasource ประมาณ `3m` ถึง `4m` และ query rate ใช้:

```promql
rate(metric_name[$__rate_interval])
```

ไม่ต้องส่ง `$__rate_interval` เป็น variable จาก Discord

---

## 12) Security Recommendation

แนะนำ:
- ใช้ Grafana Service Account Token ที่มีสิทธิ์ Viewer เท่านั้น
- ไม่ใช้ admin token
- ถ้าเปิด Grafana ให้ bot เข้าจาก network อื่น ควร allow เฉพาะ IP ของ bot
- ถ้าเป็นไปได้ ให้ใช้ HTTPS ผ่าน reverse proxy
- อย่าใส่ token ใน command channel สาธารณะ ถ้าจำเป็นให้ตั้งใน private/admin channel เท่านั้น

---

## 13) Troubleshooting

### Bot render แล้วได้ 404

ตรวจสอบ:
- Dashboard UID ถูกหรือไม่
- Panel ID ถูกหรือไม่
- Dashboard slug ไม่จำเป็นต้องถูกเสมอ แต่ UID ต้องถูก
- URL `/render/d-solo/<uid>/<slug>?panelId=<id>` ใช้ได้จากเครื่อง bot หรือไม่

### Bot render แล้วได้ 401 / 403

ตรวจสอบ:
- ต้องตั้ง API token หรือไม่
- Token มีสิทธิ์ดู dashboard หรือไม่
- Grafana anonymous access เปิดหรือไม่

### Bot render แล้ว timeout

ตรวจสอบ:
- `grafana-image-renderer` healthy หรือไม่
- Grafana ตั้งค่า renderer plugin ถูกหรือไม่
- เครื่อง Jetson Nano RAM/CPU พอหรือไม่
- ลองลด `width` / `height`
- ลองเพิ่ม timeout:

```text
[p]grafana timeout 90
```

### รูปไม่แสดง variable ตามที่ต้องการ

ตรวจสอบชื่อ variable ใน Grafana ต้องตรง เช่น:
- `job` ต้องส่งเป็น `var-job=value`
- `node` ต้องส่งเป็น `var-node=value`
- `nodename` ต้องส่งเป็น `var-nodename=value`
