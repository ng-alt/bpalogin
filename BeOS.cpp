
#ifndef BPALOGIN_H
#include "BeOS.h"
#endif

extern "C"
{
#include "bpalogin.h"
}

int debug_level = DEFAULT_DEBUG;
struct session s;
int pid = 0;

extern "C" void logwrite(char * s)
{
	FILE * f = fopen("bpalogin.log","a");
	if(f)
	{
	        fprintf(f,s);
	        fclose(f);
	}  
}

extern "C" void debug(int l,char * s,...)
{
	va_list ap;
	va_start(ap,s);
	if(debug_level > l)
	{
		char buf[256];
		
		vsprintf(buf,s,ap);
		logwrite(buf);
	}
	va_end(ap);  
}

extern "C" void critical(char *s1)
{
	BAlert * b = new BAlert("BPALogin Error",s1,"OK");
	b->Go();
//	delete b;
	logwrite(s1);
	logwrite("\n");
//	shutdown(s.listensock);
	closesocket(s.listensock);
	s.ondisconnected();
	exit_thread(0);
}
extern "C" void noncritical(char * s,...)
{
	char buf[256];
	
	va_list ap;
	va_start(ap,s);
	vsprintf(buf,s,ap);
	logwrite(buf);
	va_end(ap);             
}

extern "C" void onconnected(int listenport)
{
	BPALoginWindow * w = (BPALoginWindow *)s.pUserData;
	
	w->OnConnected();
}

extern "C" void ondisconnected()
{
	BPALoginWindow * w = (BPALoginWindow *)s.pUserData;
	
	w->OnDisconnected();
}

int main(int, char**)
{	
	BPALoginApplication	myApplication;

	myApplication.Run();

	return(0);
}

BPALoginApplication::BPALoginApplication()
		  		  : BApplication("application/x-vnd.Be-BPALogin")
{
	BPALoginWindow *aWindow;
	BRect aRect;

	// set up a rectangle and instantiate a new window
	aRect.Set(100, 80, 300, 180);
	aWindow = new BPALoginWindow(aRect);
			
	// make window visible
	aWindow->Show();
}

BPALoginWindow::BPALoginWindow(BRect frame)
				: BWindow(frame, "BPALogin v1.5a", B_TITLED_WINDOW, B_NOT_RESIZABLE | B_NOT_ZOOMABLE | B_WILL_DRAW)
{
	BRect aRect;
	BButton * fButton;
	
	aRect.Set(130, 5, 195, 25);
	m_ConnectButton = new BButton(aRect, "Connect", "Connect",new BMessage(CONNECT_MSG));
	AddChild(m_ConnectButton);
	aRect.Set(130, 30, 195, 50);
	fButton = new BButton(aRect, NULL, "Config",new BMessage(CONFIG_MSG));
	AddChild(fButton);
	aRect.Set(130, 70, 195, 90);
	fButton = new BButton(aRect, NULL, "About",new BMessage(ABOUT_MSG));
	AddChild(fButton);	
	aRect.Set(5, 5, 105, 20);

	m_Msgs = new BStringView(aRect, NULL, "Not Connected");
	AddChild(m_Msgs);

	aRect.Set(5, 75, 105, 90);
	BStringView * s = new BStringView(aRect, NULL, "BPALogin v1.5a");
	AddChild(s);
	
	m_bShutting = false;
	m_bConnected = false;
}

bool BPALoginWindow::QuitRequested()
{
	if(m_bConnected)
	{
		closesocket(s.listensock);
		s.shutdown = 1;
		m_bShutting = true;
//		OnDisconnected();
		return false;
	}
	be_app->PostMessage(B_QUIT_REQUESTED);
	return(true);
}

void BPALoginWindow::MessageReceived(BMessage* message)
{
	switch(message->what)
	{
		case CONFIG_MSG:
		{
			BPALoginConfigWindow *aWindow;
			BRect aRect;
		
			// set up a rectangle and instantiate a new window
			aRect.Set(100, 80, 300, 180);
			aWindow = new BPALoginConfigWindow(aRect);
					
			// make window visible
			aWindow->Show();
		}
			break;
		case CONNECT_MSG:
		{
			if(!m_bConnected)
			{
				m_ConnectButton->SetEnabled(false);
				Connect();
			}
			else
			{
				closesocket(s.listensock);
				s.shutdown = 1;
			}      
        }
			break;
		case ABOUT_MSG:
		{
			BPALoginAboutWindow *aWindow;
			BRect aRect;
		
			// set up a rectangle and instantiate a new window
			aRect.Set(100, 80, 400, 480);
			aWindow = new BPALoginAboutWindow(aRect);
					
			// make window visible
			aWindow->Show();
		}
			break;
		default:
			BWindow::MessageReceived(message);
	}
}

BPALoginAboutWindow::BPALoginAboutWindow(BRect frame)
				: BWindow(frame, "About BPALogin", B_MODAL_WINDOW, B_NOT_RESIZABLE | B_NOT_ZOOMABLE)
{
	BButton * fButton;
	BRect aRect;
	
	aRect.Set(5,5,frame.Width()-10+5,frame.Height()-40+5);
	BTextView * s = new BTextView(aRect, NULL, aRect,B_FOLLOW_ALL_SIDES);
	s->SetText("BPALogin v1.5a\nBPALogin is free software under the GNU General Public License\nMore Text needed here");
	s->MakeEditable(false);
	s->MakeSelectable(false);
	s->SetAlignment(B_ALIGN_CENTER);
	AddChild(s);
	aRect.Set(100,100,160,120);

	aRect.Set((frame.Width())/2-30, frame.Height() - 30, (frame.Width())/2+30, frame.Height()-10);
	fButton = new BButton(aRect, NULL, "OK",new BMessage(OK_MSG));
	AddChild(fButton);	
}

void BPALoginAboutWindow::MessageReceived(BMessage* message)
{
	switch(message->what)
	{
		case OK_MSG:
		{
			Hide();
			Quit();
		}
			break;
		default:
			BWindow::MessageReceived(message);
	}
}

int32 MainLoop(void * data)
{
	s.pUserData = data;
	
	s.debug = debug;
	s.critical = critical;
	s.noncritical = noncritical;
	s.onconnected = onconnected;
	s.ondisconnected = ondisconnected;
	s.shutdown = 0;
	
	strcpy(s.authserver,"dce-server");
	FILE * f = fopen("bpalogin.conf","r");
	if(f)
	{
		char s2[256];
		char s1[256];
		if(fgets(s1,256,f))
		{
			sscanf(s1,"%s\n",s2);
			strcpy(s.username,s2);
			if(fgets(s1,256,f))
			{
				sscanf(s1,"%s\n",s2);
				strcpy(s.password,s2);
			}
		}
		fclose(f);
	}
	if(!strcmp(s.username,"") || !strcmp(s.password,""))
	{
		BAlert * b = new BAlert("BPALogin Error","Password details not set","OK");
		b->Go();
		s.ondisconnected();
		return 0;
	}	
	s.authport = DEFAULT_AUTHPORT;
	debug_level = DEFAULT_DEBUG;
	
	s.onconnected(0);
	
	while(mainloop(&s));
	
	logout(0,&s);
	
	s.ondisconnected();
	return 0;
}

void BPALoginWindow::Connect()
{
	pid = spawn_thread(MainLoop,"BIDS2",10,this);
	resume_thread(pid);
}

void BPALoginWindow::OnConnected()
{
	Lock();
	m_Msgs->SetText("Connected");
	m_bConnected = true;
	m_ConnectButton->SetLabel("Disconnect");
	m_ConnectButton->SetEnabled(true);
	Unlock();                 
}

void BPALoginWindow::OnDisconnected()
{
	status_t s;

	Lock();
	m_Msgs->SetText("Not Connected");
	m_bConnected = false;
	m_ConnectButton->SetLabel("Connect");
	m_ConnectButton->SetEnabled(true);                 
	Unlock();                 
	if(m_bShutting)
		be_app->PostMessage(B_QUIT_REQUESTED);
	//wait_for_thread(pid,&s);
}

BPALoginConfigWindow::BPALoginConfigWindow(BRect frame)
				: BWindow(frame, "Config BPALogin", B_MODAL_WINDOW, B_NOT_RESIZABLE | B_NOT_ZOOMABLE)
{
	BButton * fButton;
	BRect aRect;
	
	aRect.Set(5,5,100,25);
	m_t1 = new BTextControl(aRect,NULL,"Username","",NULL);
	AddChild(m_t1);
	aRect.Set(5,30,100,50);
	m_t2 = new BTextControl(aRect,NULL,"Password","",NULL);
	AddChild(m_t2);
	aRect.Set((frame.Width())/2-30, frame.Height() - 30, (frame.Width())/2+30, frame.Height()-10);
	fButton = new BButton(aRect, NULL, "OK",new BMessage(OK_MSG));
	AddChild(fButton);	
	
	FILE * f = fopen("bpalogin.conf","r");
	if(f)
	{
		char s2[256];
		char s1[256];
		if(fgets(s1,256,f))
		{
			sscanf(s1,"%s\n",s2);
			m_t1->SetText(s2);
			if(fgets(s1,256,f))
			{
				sscanf(s1,"%s\n",s2);
				m_t2->SetText(s2);
			}
		}
		fclose(f);
	}
}

void BPALoginConfigWindow::MessageReceived(BMessage* message)
{
	switch(message->what)
	{
		case OK_MSG:
		{
			FILE * f = fopen("bpalogin.conf","w");
			if(f)
			{
				fprintf(f,"%s\n",m_t1->Text());
				fprintf(f,"%s\n",m_t2->Text());
				fclose(f);
			}
			Hide();
			Quit();
		}
			break;
		default:
			BWindow::MessageReceived(message);
	}
}