/*
	
	BeOS.h

*/


#ifndef BPALOGIN_H
#define BPALOGIN_H

#ifndef _APPLICATION_H
#include <Application.h>
#endif

class BPALoginApplication : public BApplication 
{
public:
	BPALoginApplication();
};

#ifndef _WINDOW_H
#include <Window.h>
#endif
#ifndef _BUTTON_H
#include <Button.h>
#endif
#ifndef _STRINGVIEW_H
#include <StringView.h>
#endif
#ifndef _TEXTVIEW_H
#include <TextView.h>
#endif
#ifndef _ALERT_H
#include <Alert.h>
#endif
#ifndef _TEXTCONTROL_H
#include <TextControl.h>
#endif

#define CONFIG_MSG 'CONF'
#define CONNECT_MSG 'CONN'
#define ABOUT_MSG 'ABOT'
#define OK_MSG 'BPAO'

class BPALoginWindow : public BWindow
{
	BStringView * m_Msgs;
	BButton * m_ConnectButton;
	bool m_bConnected;
	bool m_bShutting;
public:
	BPALoginWindow(BRect frame); 
	virtual	bool QuitRequested();
	virtual void MessageReceived(BMessage* message);
	void Connect();
	void OnConnected();
	void OnDisconnected();
};

class BPALoginAboutWindow : public BWindow
{
public:
	BPALoginAboutWindow(BRect frame); 
	virtual void MessageReceived(BMessage* message);
};

class BPALoginConfigWindow : public BWindow
{
	BTextControl * m_t1, * m_t2;
public:
	BPALoginConfigWindow(BRect frame); 
	virtual void MessageReceived(BMessage* message);
};

#endif //BPALOGIN_H
