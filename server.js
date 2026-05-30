const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json()); // Untuk memproses JSON body request
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

// --- SISTEM KEAMANAN TOTP & STATELESS SESSION TOKEN ---
const ADMIN_TOTP_SECRET = process.env.ADMIN_TOTP_SECRET || 'KAELSPINWHEEL234';

function base32Decode(base32) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const cleaned = base32.replace(/=+$/, "").toUpperCase();
    let bits = "";
    for (let i = 0; i < cleaned.length; i++) {
        const val = alphabet.indexOf(cleaned[i]);
        if (val === -1) {
            throw new Error("Invalid base32 character: " + cleaned[i]);
        }
        bits += val.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.substr(i, 8), 2));
    }
    return Buffer.from(bytes);
}

function generateTOTP(secret, time) {
    const key = base32Decode(secret);
    const counter = Buffer.alloc(8);
    counter.writeUInt32BE(0, 0);
    counter.writeUInt32BE(time, 4);

    const hmac = crypto.createHmac('sha1', key);
    hmac.update(counter);
    const hmacResult = hmac.digest();

    const offset = hmacResult[hmacResult.length - 1] & 0xf;
    const code = ((hmacResult[offset] & 0x7f) << 24) |
                 ((hmacResult[offset + 1] & 0xff) << 16) |
                 ((hmacResult[offset + 2] & 0xff) << 8) |
                 (hmacResult[offset + 3] & 0xff);

    return (code % 1000000).toString().padStart(6, '0');
}

function verifyTOTP(token, secret, window = 1) {
    const epoch = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epoch / 30);
    
    for (let i = -window; i <= window; i++) {
        try {
            const expected = generateTOTP(secret, counter + i);
            if (token === expected) return true;
        } catch (e) {
            console.error("Gagal verifikasi TOTP:", e);
            return false;
        }
    }
    return false;
}

function generateSessionToken(secret) {
    const expires = Date.now() + 24 * 60 * 60 * 1000; // Sesi valid selama 24 jam
    const data = expires.toString();
    const signature = crypto.createHmac('sha256', secret).update(data).digest('hex');
    return `${data}.${signature}`;
}

function verifySessionToken(token, secret) {
    if (!token) return false;
    const parts = token.split('.');
    if (parts.length !== 2) return false;
    const [expiresStr, signature] = parts;
    const expires = parseInt(expiresStr);
    if (isNaN(expires) || expires < Date.now()) return false;
    const expectedSignature = crypto.createHmac('sha256', secret).update(expiresStr).digest('hex');
    return signature === expectedSignature;
}

// --- REST API ENDPOINTS ---
app.post('/api/auth/login', (req, res) => {
    const { code } = req.body;
    if (!code) {
        return res.status(400).json({ success: false, error: 'Masukkan kode OTP!' });
    }
    
    const isValid = verifyTOTP(code, ADMIN_TOTP_SECRET);
    if (isValid) {
        const token = generateSessionToken(ADMIN_TOTP_SECRET);
        return res.json({ success: true, token });
    } else {
        return res.status(400).json({ success: false, error: 'Kode OTP salah atau kedaluwarsa!' });
    }
});

app.get('/api/auth/setup', (req, res) => {
    const issuer = 'KaelSpinWheel';
    const label = 'Admin';
    const otpauthUri = `otpauth://totp/${issuer}:${label}?secret=${ADMIN_TOTP_SECRET}&issuer=${issuer}`;
    const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpauthUri)}`;
    
    return res.json({
        secret: ADMIN_TOTP_SECRET,
        qrCodeUrl: qrCodeUrl
    });
});

// Menyajikan file statis dari folder public
app.use(express.static(path.join(__dirname, 'public')));

// Fallback untuk admin dashboard
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// --- CENTRAL STATE MANAGER (Terpusat di Server agar Anti-Reset & Anti-Manipulasi) ---
let state = {
    participants: [],
    winnersHistory: [],
    currentWinner: null,
    timerState: {
        isStreaming: false,
        streamElapsedSeconds: 0,
        nextAbsenSeconds: 15 * 60,
        currentCheckpoint: 0
    },
    spinState: {
        isSpinning: false,
        isContinuous: false,
        isStopping: false,
        angularVelocity: 0,
        winnerIdx: -1
    },
    rawInput: "Andi:1\nBudi:1\nCitra:1\nDewi:1",
    showTransparency: true // Papan Transparansi OBS default menyala
};

const colors = [
    '#ff7675', '#00a8ff', '#9c88ff', '#fbc531', '#2ed573', 
    '#e1b12c', '#8c7ae6', '#00d2d3', '#ff9f43', '#10ac84',
    '#0984e3', '#6c5ce7', '#fdcb6e', '#d63031', '#fd79a8'
];

// Helper Sinkronisasi Dua Arah
function syncRawInputFromParticipants() {
    state.rawInput = state.participants.map(p => `${p.name}:${p.weight}`).join('\n');
}

function recalculateAnglesAndTotalWeight() {
    let totalWeight = 0;
    state.participants.forEach(p => {
        totalWeight += p.weight;
    });
    
    if (totalWeight === 0) return 0;
    
    let currentAngle = 0;
    state.participants.forEach(p => {
        const fraction = p.weight / totalWeight;
        p.startAngle = currentAngle;
        p.endAngle = currentAngle + (fraction * 2 * Math.PI);
        currentAngle = p.endAngle;
    });
    
    return totalWeight;
}

// Helper untuk memproses data input mentah menjadi data juring terstruktur (Mencegah kehilangan checkpoints)
function processParticipants(rawText) {
    state.rawInput = rawText;
    const lines = rawText.trim().split(/[\n,]+/).map(s => s.trim()).filter(s => s.length > 0);
    
    let parts = [];
    let totalWeight = 0;
    
    lines.forEach((line, idx) => {
        let name = line;
        let weight = 1;
        
        if (line.includes(':')) {
            const splitParts = line.split(':');
            name = splitParts[0].trim();
            weight = parseFloat(splitParts[1]) || 1;
        }
        
        if (name.length > 0 && weight > 0) {
            // Cek apakah partisipan ini sudah ada sebelumnya untuk mempertahankan data checkpoint & baseWeight
            const existing = state.participants.find(p => p.name.toLowerCase() === name.toLowerCase());
            const checkpoints = existing ? existing.checkpoints : [false, false, false, false, false, false];
            const baseWeight = existing ? existing.baseWeight : (line.includes(':') ? Math.max(1, weight - checkpoints.filter(c => c).length) : 1);
            
            // Hitung ulang bobot total = baseWeight + jumlah checkpoints aktif
            const activeCheckpointsCount = checkpoints.filter(c => c).length;
            const finalWeight = baseWeight + activeCheckpointsCount;
            
            parts.push({
                name: name,
                weight: finalWeight,
                baseWeight: baseWeight,
                checkpoints: checkpoints,
                color: colors[idx % colors.length]
            });
            totalWeight += finalWeight;
        }
    });

    // Hitung sudut start & end juring secara proporsional berdasarkan bobot
    let currentAngle = 0;
    parts.forEach(p => {
        const fraction = p.weight / totalWeight;
        p.startAngle = currentAngle;
        p.endAngle = currentAngle + (fraction * 2 * Math.PI);
        currentAngle = p.endAngle;
    });

    state.participants = parts;
    return totalWeight;
}

// Inisialisasi data default awal
let currentTotalWeight = processParticipants(state.rawInput);

// --- TIMER LOOP TERPUSAT DI SERVER (Stopwatch tetap berjalan walau browser ditutup!) ---
setInterval(() => {
    if (state.timerState.isStreaming) {
        state.timerState.streamElapsedSeconds++;
        
        if (state.timerState.nextAbsenSeconds > 0) {
            state.timerState.nextAbsenSeconds--;
        } else {
            // Alarm berbunyi! Kirim event alarm ke OBS & Admin
            io.emit('timer:alarm', {});
            
            // Pindahkan checkpoint secara otomatis ke 15 menit berikutnya
            const checkpoints = [0, 15, 30, 45, 60, 75, 90];
            const currentIndex = checkpoints.indexOf(state.timerState.currentCheckpoint);
            if (currentIndex !== -1 && currentIndex < checkpoints.length - 1) {
                state.timerState.currentCheckpoint = checkpoints[currentIndex + 1];
                state.timerState.streamElapsedSeconds = state.timerState.currentCheckpoint * 60;
                state.timerState.nextAbsenSeconds = 15 * 60;
            } else {
                state.timerState.nextAbsenSeconds = 15 * 60;
            }
        }
        
        // Peringatan serah terima streamer menit ke-90
        if (state.timerState.streamElapsedSeconds >= 90 * 60) {
            state.timerState.isStreaming = false;
            io.emit('timer:handover', {});
        }

        // Siarkan pembaruan timer ke seluruh layar setiap detik
        io.emit('state:timer', state.timerState);
    }
}, 1000);

// --- WEBSOCKET REAL-TIME EVENTS (Socket.io) ---
io.on('connection', (socket) => {
    // Cek token sesi admin pada saat handshaking / koneksi awal
    const token = socket.handshake.auth?.token;
    const isAdmin = verifySessionToken(token, ADMIN_TOTP_SECRET);
    socket.isAdmin = isAdmin;
    
    if (isAdmin) {
        console.log(`Admin TEROTORISASI terhubung [ID: ${socket.id}]`);
    } else {
        console.log(`Klien biasa/OBS terhubung [ID: ${socket.id}]`);
    }

    // Middleware packet level: filter ketat semua event 'admin:*'
    socket.use(([event, ...args], next) => {
        if (event.startsWith('admin:') && !socket.isAdmin) {
            console.warn(`[KEAMANAN] Perintah admin ditolak dari socket non-admin [ID: ${socket.id}]: event = ${event}`);
            return next(new Error('Akses admin tidak sah!'));
        }
        next();
    });

    // 1. Kirim state lengkap terupdate saat klien baru pertama kali terhubung
    socket.emit('init', {
        participants: state.participants,
        totalWeight: currentTotalWeight,
        winnersHistory: state.winnersHistory,
        timerState: state.timerState,
        spinState: state.spinState,
        rawInput: state.rawInput,
        currentWinner: state.currentWinner,
        showTransparency: state.showTransparency,
        isAdmin: socket.isAdmin // Kirim info hak akses ke sisi client
    });

    // 2. Admin memperbarui data nama & bobot
    socket.on('admin:update_participants', (rawText) => {
        currentTotalWeight = processParticipants(rawText);
        io.emit('state:participants', {
            participants: state.participants,
            totalWeight: currentTotalWeight,
            rawInput: state.rawInput
        });
    });

    // 3. Admin memicu putaran roda kencang tak terbatas
    socket.on('admin:spin', () => {
        state.spinState.isSpinning = true;
        state.spinState.isContinuous = true;
        state.spinState.isStopping = false;
        state.spinState.angularVelocity = 0.54;
        state.spinState.winnerIdx = -1;
        state.currentWinner = null;
        
        io.emit('state:spin', state.spinState);
    });

    // 4. Admin menekan tombol STOP ➜ Server mengundi pemenang secara matematis adil (Weighted Random)
    socket.on('admin:stop', () => {
        if (state.participants.length === 0) return;
        
        // Hitung total bobot
        let totalW = 0;
        state.participants.forEach(p => totalW += p.weight);
        
        // Algoritme Seleksi Bobot Adil (Anti-Manipulasi)
        let rand = Math.random() * totalW;
        let winnerIdx = 0;
        let sum = 0;
        for (let i = 0; i < state.participants.length; i++) {
            sum += state.participants[i].weight;
            if (rand <= sum) {
                winnerIdx = i;
                break;
            }
        }

        state.spinState.isContinuous = false;
        state.spinState.isStopping = true;
        state.spinState.winnerIdx = winnerIdx;

        // Siarkan instruksi stop & index pemenang terpilih ke seluruh layar (OBS & Admin melambat sinkron)
        io.emit('state:stop', state.spinState);
    });

    // 5. Roda berhenti melambat & menyatakan pemenang secara final
    socket.on('wheel:stop_complete', (winnerIdx) => {
        // Mencegah duplikasi entri riwayat jika ada multi-screen
        if (!state.spinState.isSpinning) return;
        
        state.spinState.isSpinning = false;
        state.spinState.isStopping = false;
        state.spinState.angularVelocity = 0;
        
        if (winnerIdx >= 0 && winnerIdx < state.participants.length) {
            const winner = state.participants[winnerIdx];
            state.currentWinner = winner;
            state.winnersHistory.unshift(winner.name);
            
            io.emit('state:winner_declared', {
                winner: winner,
                winnersHistory: state.winnersHistory,
                spinState: state.spinState
            });
        }
    });

    // 6. Kontrol Timer Stopwatch (Mulai / Jeda)
    socket.on('admin:toggle_stream', () => {
        state.timerState.isStreaming = !state.timerState.isStreaming;
        io.emit('state:timer', state.timerState);
    });

    // 7. Kontrol Reset Timer
    socket.on('admin:reset_stream', () => {
        state.timerState.isStreaming = false;
        state.timerState.streamElapsedSeconds = 0;
        state.timerState.nextAbsenSeconds = 15 * 60;
        state.timerState.currentCheckpoint = 0;
        io.emit('state:timer', state.timerState);
    });

    // 8. Klik Manual Checkpoint Absen Linimasa
    socket.on('admin:set_checkpoint', (minutes) => {
        state.timerState.currentCheckpoint = minutes;
        state.timerState.streamElapsedSeconds = minutes * 60;
        state.timerState.nextAbsenSeconds = (minutes === 90) ? 0 : 15 * 60;
        io.emit('state:timer', state.timerState);
    });

    // 9. Hapus nama pemenang terpilih dari daftar roda
    socket.on('admin:remove_winner', (winnerName) => {
        if (!winnerName) return;
        
        const lines = state.rawInput.trim().split(/[\n,]+/);
        const updatedLines = lines.filter(line => {
            let name = line;
            if (line.includes(':')) {
                name = line.split(':')[0].trim();
            }
            return name.toLowerCase() !== winnerName.toLowerCase();
        });

        state.rawInput = updatedLines.join('\n');
        currentTotalWeight = processParticipants(state.rawInput);
        state.currentWinner = null;
        
        io.emit('state:participants', {
            participants: state.participants,
            totalWeight: currentTotalWeight,
            rawInput: state.rawInput
        });
        io.emit('state:winner_dismissed');
    });

    // 10. Mengosongkan daftar riwayat pemenang
    socket.on('admin:clear_history', () => {
        state.winnersHistory = [];
        io.emit('state:history_cleared', { winnersHistory: [] });
    });

    // 11. Hapus item riwayat pemenang secara parsial
    socket.on('admin:delete_history_item', (idx) => {
        if (idx >= 0 && idx < state.winnersHistory.length) {
            state.winnersHistory.splice(idx, 1);
            io.emit('state:history_updated', { winnersHistory: state.winnersHistory });
        }
    });

    // 12. Toggle checkpoint absensi secara interaktif
    socket.on('admin:toggle_checkpoint', (data) => {
        const { name, cpIdx } = data;
        const p = state.participants.find(part => part.name.toLowerCase() === name.toLowerCase());
        if (p) {
            p.checkpoints[cpIdx] = !p.checkpoints[cpIdx];
            // Hitung ulang bobot total = baseWeight + jumlah checkpoints aktif
            const activeCount = p.checkpoints.filter(c => c).length;
            p.weight = p.baseWeight + activeCount;
            
            syncRawInputFromParticipants();
            currentTotalWeight = recalculateAnglesAndTotalWeight();
            
            io.emit('state:participants', {
                participants: state.participants,
                totalWeight: currentTotalWeight,
                rawInput: state.rawInput
            });
        }
    });

    // 13. Ubah bobot dasar (baseWeight) penonton
    socket.on('admin:change_base_weight', (data) => {
        const { name, newBaseWeight } = data;
        const p = state.participants.find(part => part.name.toLowerCase() === name.toLowerCase());
        if (p) {
            p.baseWeight = parseFloat(newBaseWeight) || 1;
            const activeCount = p.checkpoints.filter(c => c).length;
            p.weight = p.baseWeight + activeCount;
            
            syncRawInputFromParticipants();
            currentTotalWeight = recalculateAnglesAndTotalWeight();
            
            io.emit('state:participants', {
                participants: state.participants,
                totalWeight: currentTotalWeight,
                rawInput: state.rawInput
            });
        }
    });

    // 14. Tambah partisipan baru secara instan
    // 14. Tambah partisipan baru / Absen cepat via input berulang (Keyboard check-in)
    socket.on('admin:add_new_participant', (data) => {
        const { name, baseWeight } = data;
        const trimmedName = name ? name.trim() : '';
        if (trimmedName.length === 0) return;

        // Cari tahu index checkpoint aktif saat ini berdasarkan stopwatch server
        const checkpointsList = [0, 15, 30, 45, 60, 75];
        const cpIdx = checkpointsList.indexOf(state.timerState.currentCheckpoint);

        // Cari apakah peserta sudah terdaftar sebelumnya
        const existing = state.participants.find(p => p.name.toLowerCase() === trimmedName.toLowerCase());

        if (existing) {
            // JIKA SUDAH ADA: Otomatis tandai checkpoint aktif saat ini sebagai TRUE (Hadir)
            if (cpIdx >= 0 && cpIdx <= 5) {
                existing.checkpoints[cpIdx] = true;
                // Hitung ulang bobot total = baseWeight + total checkpoints aktif
                const activeCount = existing.checkpoints.filter(c => c).length;
                existing.weight = existing.baseWeight + activeCount;
                console.log(`[RAPID CHECK-IN] ${existing.name} otomatis absen pada checkpoint ${state.timerState.currentCheckpoint}m via input ulang.`);
            }
        } else {
            // JIKA BELUM ADA: Daftarkan sebagai peserta baru
            const bw = parseFloat(baseWeight) || 1;
            const checkpoints = [false, false, false, false, false, false];
            
            // Otomatis tandai juga checkpoint aktif saat ini untuk pendatang baru!
            if (cpIdx >= 0 && cpIdx <= 5) {
                checkpoints[cpIdx] = true;
            }

            const activeCount = checkpoints.filter(c => c).length;
            
            state.participants.push({
                name: trimmedName,
                baseWeight: bw,
                weight: bw + activeCount,
                checkpoints: checkpoints,
                color: colors[state.participants.length % colors.length]
            });
            console.log(`[NEW PARTICIPANT] ${trimmedName} ditambahkan dan otomatis absen pada checkpoint ${state.timerState.currentCheckpoint}m.`);
        }
        
        syncRawInputFromParticipants();
        currentTotalWeight = recalculateAnglesAndTotalWeight();
        
        io.emit('state:participants', {
            participants: state.participants,
            totalWeight: currentTotalWeight,
            rawInput: state.rawInput
        });
    });

    // 15. Absen/checkin seluruh peserta yang terdaftar untuk checkpoint saat ini
    socket.on('admin:checkin_all_active', () => {
        const checkpointsList = [0, 15, 30, 45, 60, 75];
        const cpIdx = checkpointsList.indexOf(state.timerState.currentCheckpoint);
        
        if (cpIdx >= 0 && cpIdx <= 5) {
            state.participants.forEach(p => {
                p.checkpoints[cpIdx] = true;
                const activeCount = p.checkpoints.filter(c => c).length;
                p.weight = p.baseWeight + activeCount;
            });
            
            syncRawInputFromParticipants();
            currentTotalWeight = recalculateAnglesAndTotalWeight();
            
            io.emit('state:participants', {
                participants: state.participants,
                totalWeight: currentTotalWeight,
                rawInput: state.rawInput
            });
        }
    });

    // 16. Toggle visibilitas Papan Transparansi di layar OBS
    socket.on('admin:toggle_obs_transparency', (show) => {
        state.showTransparency = show;
        io.emit('state:transparency', show);
    });

    // 17. Menutup modal pemenang dan menghapus state pemenang saat ini di server
    socket.on('admin:dismiss_winner', () => {
        state.currentWinner = null;
        io.emit('state:winner_dismissed');
    });

    socket.on('disconnect', () => {
        console.log(`Klien terputus [ID: ${socket.id}]`);
    });
});

// Jalankan Web Server
server.listen(PORT, () => {
    console.log(`=== KAEL SPIN WHEEL SERVER PRO BERJALAN ===`);
    console.log(`Layar Utama (OBS): http://localhost:${PORT}`);
    console.log(`Panel Admin (Streamer): http://localhost:${PORT}/admin`);
    console.log(`===========================================`);
});
