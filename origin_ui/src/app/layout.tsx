import './globals.css'
import {ThemeProviderClient} from "@/public/theme";

export const metadata = {
  title: 'Pelican Platform',
  description: 'Software designed to make data distribution easy',
}

export default function RootLayout({
                                     children,
                                   }: {
  children: React.ReactNode
}) {
  return (
      <html lang="en">
      <ThemeProviderClient>
        <body>
            {children}
        </body>
      </ThemeProviderClient>
      </html>
  )
}
