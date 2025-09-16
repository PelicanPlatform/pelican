import React from "react";

import { Footer, Layout, Navbar } from 'nextra-theme-docs'
import { Head } from 'nextra/components'
import { getPageMap } from 'nextra/page-map'

import { AppRouterCacheProvider } from '@mui/material-nextjs/v15-appRouter';

import ThemeProvider from '@/components/ThemeProvider'

// Required for theme styles, previously was imported under the hood
import 'nextra-theme-docs/style.css'

export const metadata = {
	title: "Pelican Documentation",
	description: "Documentation for Pelican, software made to deliver.",
	openGraph: {
		title: "Pelican Documentation",
		description: "Documentation for Pelican, software made to deliver.",
	},
	icons: {
		icon: '/PelicanPlatformLogoIcon.svg',
	},
}

const navbar = <Navbar
		logo={
			<>
				<img alt="Pelican Icon" loading="lazy" width="36" height="36" decoding="async" data-nimg="1"
						 src="/PelicanPlatformLogoIcon.svg"
				/>
				<span style={{paddingLeft: 12, fontSize: "1.6rem"}}>Pelican</span>
			</>
		}
		projectLink="https://github.com/pelicanPlatform/pelican"
/>
const footer = (
		<Footer className="flex-col items-center md:items-start">
			This project is supported by National Science Foundation under Cooperative Agreement OAC-2331480. Any opinions, findings, conclusions or recommendations expressed in this material are those of the authors and do not necessarily reflect the views of the National Science Foundation.
		</Footer>
)



export default async function RootLayout({ children }) {
	return (
		<html
			// Not required, but good for SEO
			lang="en"
			// Required to be set
			dir="ltr"
			// Suggested by `next-themes` package https://github.com/pacocoursey/next-themes#with-app
			suppressHydrationWarning
		>
			<Head
				backgroundColor={{
					dark: 'rgb(15, 23, 42)',
					light: 'rgb(255,255,255)'
				}}
				color={{
					hue: { dark: 200, light: 200 },
					saturation: { dark: 100, light: 100 }
				}}
			>
				<link rel="stylesheet" type="text/css" href="/style.css"/>
			</Head>
			<AppRouterCacheProvider>
				<body>
					<Layout
						navbar={navbar}
						pageMap={await getPageMap()}
						docsRepositoryBase="https://github.com/PelicanPlatform/pelican/tree/main/docs"
						editLink="Edit this page on GitHub"
						sidebar={{ defaultMenuCollapseLevel: 1 }}
						footer={footer}
						// ...Your additional theme config options
					>
						{}
						<ThemeProvider>
							{children}
						</ThemeProvider>
					</Layout>
				</body>
			</AppRouterCacheProvider>
		</html>
	)
}
