# Quick Start Guide - SafeWeb IDS

## 🚀 Start the IDS

```bash
cd "/home/asmit/Desktop/pata nhai"
sudo ./start_ids.sh
```

## 🌐 Access Dashboard

Open browser: **http://localhost:5000**

Login:
- Username: `admin`
- Password: `admin123`

## 📡 Capture Packets

1. Select network interface (e.g., `eth0`)
2. Click **"Start Capture"** button
3. Wait 5-10 seconds for capture to complete
4. View results in **"Recent Analysis"** section

## 📊 View Results

- **Dashboard**: Overview + recent analysis
- **Packet Analysis**: Protocol distribution
- **ML Predictions**: Anomaly detection results
- **Visualizations**: Charts and graphs
- **Saved Captures**: Download .pcap files

## 🔄 Auto-Refresh

All pages update automatically:
- **Dashboard metrics**: Every 3 seconds
- **Recent analysis**: Every 5 seconds
- **Live capture stats**: Every 0.5 seconds

No need to manually refresh!

## 🧪 Test the System

```bash
env/bin/python test_ids.py
```

## 🛑 Stop the IDS

Press `Ctrl+C` in the terminal

## 📝 Check Logs

The IDS logs everything to the terminal. Look for:
- `INFO:root:Captured X packets` - Successful capture
- `INFO:root:Protocol counts` - Traffic analysis
- Errors will show with `ERROR:root:`

## 🔍 Detected Threats

The IDS now focuses on:
- DoS / DDoS-style high-volume attacks (rule-based threshold)
- ML-detected anomalies (optional)

## ⚙️ Configure Settings

Go to **Settings** page to adjust:
- Detection thresholds
- Notification email
- ML model selection
- Upload custom models

## 📁 Data Files

- **analysis_history.json**: All analysis results
- **settings.json**: Configuration
- **data/captures/**: Saved .pcap files
- **users.json**: User accounts

## 🆘 Troubleshooting

### No packets captured?
- Run with `sudo` (required for packet capture)
- Check interface is correct (use `ip link show`)
- Verify you have network traffic

### Pages not updating?
- Check browser console for errors (F12)
- Verify API endpoints are working
- Restart the server

### Permission errors?
```bash
sudo chmod -R 777 data
sudo env/bin/python flask_app.py
```

## 📞 Support

Check these files for details:
- `COMPLETE_FIX_SUMMARY.md` - Full fix documentation
- `FIXES_APPLIED.md` - Technical details
- `README.md` - Complete project documentation

---

**You're all set! Start capturing and analyzing network traffic.** 🎉
