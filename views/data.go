package views

import "log"

const (
	AlertLvlError   = "danger"
	AlertLvlWarning = "warning"
	AlertLvlInfo    = "info"
	AlertLvlSuccess = "success"

	AlertMsgGeneric = "Something went wrong. Please try again, and contact us if the problem persists."
)

type Alert struct {
	Level   string
	Message string
}
type Data struct {
	Alert *Alert
	Yield interface{}
}

type PulbicError interface {
	error
	Public() string
}

func (d *Data) SetAlert(err error) {
	var msg string
	if pErr, ok := err.(PulbicError); ok {
		msg = pErr.Public()
	} else {
		log.Println(err)
		msg = AlertMsgGeneric
	}
	d.Alert = &Alert{
		Level:   AlertLvlError,
		Message: msg,
	}
}

func (d *Data) AlertError(msg string) {
	d.Alert = &Alert{
		Level:   AlertLvlError,
		Message: msg,
	}
}
