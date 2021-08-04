package main

import (
	"os"
	"fmt"
	"errors"
	"strings"
	"strconv"
	
	"net/http"
	"io/ioutil"
	"path/filepath"
	"encoding/json"

	"github.com/gorilla/mux"
        "github.com/gorilla/sessions"
        "github.com/DusanKasan/parsemail"

        "github.com/aws/aws-sdk-go/aws"
        "github.com/aws/aws-sdk-go/aws/credentials"
        "github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"

        sb "github.com/CyCoreSystems/sendinblue"
)

type LoginRecord struct {
	Username string `json:"uname"`
	Password string `json:"passwd"`
}

type EmailList struct {
	ID string `json:"id"`
	Subject string `json:"subject"`
	From string `json:"from"`
	Body string `json:"body"`
	File string `json:"file"`
	CTE string `json:"cte"`
}

type ReturnList struct {
	Filename string
	Email parsemail.Email
}

type Settings struct {
	FirstName string `json:"firstname"`
	LastName string `json:"lastname"`
	EmailAddr string `json:"emailaddr"`
	SendInBlueKey string `json:"sendinbluekey"`
	AWSAccessKey string `json:"awsaccesskey"`
	AWSSecretKey string `json:"awssecretkey"`
	S3Bucket string `json:"s3bucket"`
	PasswordProtect bool `json:"passwordprotect"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var fname string
var lname string
var emailaddr string
var sendinbluekey string
var awsaccesskey string
var awssecretkey string
var s3bucket string

var store = sessions.NewFilesystemStore(os.TempDir(), []byte("authkey"))

func GetFiles(user string) (error) {
	var settings Settings

        if _, err := os.Stat("./settings.conf"); os.IsNotExist(err) {
		return err
        } 

	jsn, err := ioutil.ReadFile("./settings.conf")
	if err != nil {
		return err
	}

	err = json.Unmarshal(jsn, &settings)
	if err != nil {
		return err
	}

        creds := credentials.NewStaticCredentials(settings.AWSAccessKey, settings.AWSSecretKey, "")
        _, err = creds.Get()
        if err != nil {
                return err 
        }

        cfg := aws.NewConfig().WithRegion("us-east-1").WithCredentials(creds)
        cfg.Region = aws.String("us-east-1")
        sess, err := session.NewSession(cfg)

	svc := s3.New(sess)
	input := &s3.ListObjectsInput {
		Bucket: aws.String(settings.S3Bucket),
	}

	result, err := svc.ListObjects(input)
	if err != nil {
		return err 
	}

        if _, err := os.Stat("./mail/" + user); os.IsNotExist(err) {
		os.MkdirAll("./mail/" + user, 0755)
        }

	for _, key := range result.Contents {
		f, err := os.OpenFile("./mail/" + user + "/" + *key.Key, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return err 
		}
		defer f.Close()

		downloader := s3manager.NewDownloader(sess)
		_, err = downloader.Download(f,
			&s3.GetObjectInput {
				Bucket: aws.String(settings.S3Bucket),
				Key: aws.String(*key.Key),
		})

		if err != nil {
			f.Close()
			return err 
		}

		input := &s3.DeleteObjectInput {
			Bucket: aws.String(settings.S3Bucket),
			Key: aws.String(*key.Key),
		}

		svc.DeleteObject(input)
	}

        return nil 
}

func GetEmailsMetaData(user string) ([]ReturnList, error) {
	var emails []ReturnList //parsemail.Email

	files, err := filepath.Glob("./mail/" + user + "/*")
	if err != nil {
		return emails, err
	}

	if len(files) == 0 {
		return emails, errors.New("no emails")
	}

	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		if info.IsDir() {
			continue
		}

		f, err := os.Open(file)
		if err != nil {
			return emails, err
		}
		defer f.Close()

		fparts := strings.Split(file, "/")

		tmprl := ReturnList{}
		tmprl.Filename = fparts[len(fparts) - 1] 

	        email, err := parsemail.Parse(f) // returns Email struct and error
		tmprl.Email = email
		emails = append(emails, tmprl)
	}

	return emails, nil
}

func handleWhoAreYou(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Defiant.Mail\n")
}

func handleSplash(w http.ResponseWriter, r *http.Request) {

        if _, err := os.Stat("./settings.conf"); os.IsNotExist(err) {
		http.Redirect(w, r, "/setup", 301)
		return
        } else {
		var settings Settings

		if _, err := os.Stat("./settings.conf"); os.IsNotExist(err) {
			http.Redirect(w, r, "/setup", 301)
			return
		} 

		jsn, err := ioutil.ReadFile("./settings.conf")
		if err != nil {
			fmt.Fprintf(w, "failed," + err.Error())
			return
		}

		err = json.Unmarshal(jsn, &settings)
		if err != nil {
			fmt.Fprintf(w, "failed," + err.Error())
			return
		}

		if settings.PasswordProtect == true {
			http.Redirect(w, r, "/showlogin", 301)
		} else {
			http.Redirect(w, r, "/mail", 301)
			return
		}
	}
}

func handleMail(w http.ResponseWriter, r *http.Request) {
	var settings Settings

        if _, err := os.Stat("./settings.conf"); os.IsNotExist(err) {
		return 
        } 

	jsn, err := ioutil.ReadFile("./settings.conf")
	if err != nil {
		return 
	}

	err = json.Unmarshal(jsn, &settings)
	if err != nil {
		return 
	}

	if settings.PasswordProtect == true {
		session, _ := store.Get(r, "defiantmail")

		auth, ok := session.Values["auth"].(bool)
		if !ok {
			http.Redirect(w, r, "/", 301)
			return
		}

		if ! auth {
			http.Redirect(w, r, "/", 301)
			return
		}
	}

	splashhtml, err := ioutil.ReadFile("mail.html")
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}

	w.Write(splashhtml)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var loginrec LoginRecord

        body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return
	}
        defer r.Body.Close()

	err = json.Unmarshal(body, &loginrec)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return
	}

	ok, err := Authenticate(loginrec.Username, loginrec.Password)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return
	}

	if !ok {
		fmt.Fprintf(w, "failed," + loginrec.Username)
		return
	}

        session, err := store.Get(r, "defiantmail")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

        session.Values["auth"] = true
        session.Save(r, w)

	fmt.Fprintf(w, "success," + loginrec.Username)
	return
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
        session, _ := store.Get(r, "defiantmail")

        session.Options.MaxAge = -1
        session.Values["auth"] = false
        session.Save(r, w)

        http.Redirect(w, r, "/", 301)
}

func handleGetMail(w http.ResponseWriter, r *http.Request) {
	var list []EmailList
	var settings Settings

        if _, err := os.Stat("./settings.conf"); os.IsNotExist(err) {
		http.Redirect(w, r, "/setup", 301)
		return 
        } 

	sjsn, err := ioutil.ReadFile("./settings.conf")
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return 
	}

	err = json.Unmarshal(sjsn, &settings)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return 
	}

	if settings.PasswordProtect == true {
		session, _ := store.Get(r, "defiantmail")

		auth, ok := session.Values["auth"].(bool)
		if !ok {
			http.Redirect(w, r, "/", 301)
			return
		}

		if ! auth {
			http.Redirect(w, r, "/", 301)
			return
		}
	}

	username := settings.FirstName
	
	err = GetFiles(username)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return
	}

	emails, err := GetEmailsMetaData(username)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return
	}

	for _, mail := range emails {
		tmplist := EmailList{}
		tmplist.ID = mail.Email.MessageID
		tmplist.Subject = mail.Email.Subject
		tmplist.From = mail.Email.From[0].String()
		tmplist.CTE = mail.Email.CTE
		if mail.Email.HTMLBody == "" {
			tmplist.Body = mail.Email.TextBody
		} else {
			tmplist.Body = mail.Email.HTMLBody
		}
		tmplist.File = mail.Filename
		list = append(list, tmplist)
	}

	jsn, err := json.Marshal(list)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return
	}

	w.Write(jsn)
}

func handleDeleteMail(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("username")
	mid := r.FormValue("emailid")

	var settings Settings

        if _, err := os.Stat("./settings.conf"); os.IsNotExist(err) {
		http.Redirect(w, r, "/setup", 301)
		return 
        } 

	sjsn, err := ioutil.ReadFile("./settings.conf")
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return 
	}

	err = json.Unmarshal(sjsn, &settings)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return 
	}

	if settings.PasswordProtect == true {
		session, _ := store.Get(r, "defiantmail")

		auth, ok := session.Values["auth"].(bool)
		if !ok {
			http.Redirect(w, r, "/", 301)
			return
		}

		if ! auth {
			http.Redirect(w, r, "/", 301)
			return
		}
	}

	err = os.Remove("./mail/" + user + "/" + mid)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return;
	}

	fmt.Fprintf(w, "success," + mid)
}

func handleDeleteAllMail(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("username")

	var settings Settings

        if _, err := os.Stat("./settings.conf"); os.IsNotExist(err) {
		http.Redirect(w, r, "/setup", 301)
		return 
        } 

	sjsn, err := ioutil.ReadFile("./settings.conf")
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return 
	}

	err = json.Unmarshal(sjsn, &settings)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return 
	}

	if settings.PasswordProtect == true {
		session, _ := store.Get(r, "defiantmail")

		auth, ok := session.Values["auth"].(bool)
		if !ok {
			http.Redirect(w, r, "/", 301)
			return
		}

		if ! auth {
			http.Redirect(w, r, "/", 301)
			return
		}
	}


	files, err := filepath.Glob("./mail/" + user + "/*")
	if err != nil {
		fmt.Fprintf(w, "failed" + err.Error())
		return 
	}

	for _, file := range files {
		err := os.Remove("./" + file)
		if err != nil {
			fmt.Fprintf(w, "failed," + err.Error())
			return;
		}
	}

	fmt.Fprintf(w, "success,all")
}

func handleSendEmail(w http.ResponseWriter, r *http.Request) {
        var tolist []*sb.Address
	var settings Settings

        if _, err := os.Stat("./settings.conf"); os.IsNotExist(err) {
		http.Redirect(w, r, "/setup", 301)
		return 
        } 

	jsn, err := ioutil.ReadFile("./settings.conf")
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return 
	}

	err = json.Unmarshal(jsn, &settings)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return 
	}

	if settings.PasswordProtect == true {
		session, _ := store.Get(r, "defiantmail")

		auth, ok := session.Values["auth"].(bool)
		if !ok {
			http.Redirect(w, r, "/", 301)
			return
		}

		if ! auth {
			http.Redirect(w, r, "/", 301)
			return
		}
	}

	fromname := r.FormValue("fromname")
	frommail := r.FormValue("frommail")
	subject := r.FormValue("subject")
	tomails := r.FormValue("tomails")
	body := r.FormValue("body")

        fromaddr := sb.Address{}
        fromaddr.Name = fromname 
        fromaddr.Email = frommail 

	parts := strings.Split(tomails, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
	        toaddr := &sb.Address{}
		toaddr.Name =  part
	        toaddr.Email = part 

		tolist = append(tolist, toaddr)
	}

        msg := sb.Message{}

        msg.Sender = &fromaddr
        msg.To = tolist
        msg.Subject = subject
	msg.HTMLContent = body 

        err = msg.Send(settings.SendInBlueKey)
        if err != nil {
                fmt.Fprintf(w, "failed," + err.Error())
                return
        }

        fmt.Fprintf(w, "success,nil")
        return
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	splashhtml, err := ioutil.ReadFile("setup.html")
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}

	var settings Settings

        if _, err := os.Stat("./settings.conf"); os.IsNotExist(err) {
		w.Write(splashhtml)
		return 
        } 

	jsn, err := ioutil.ReadFile("./settings.conf")
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return 
	}

	err = json.Unmarshal(jsn, &settings)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return 
	}

	if settings.PasswordProtect == true {
		session, _ := store.Get(r, "defiantmail")

		auth, ok := session.Values["auth"].(bool)
		if !ok {
			http.Redirect(w, r, "/", 301)
			return
		}

		if ! auth {
			http.Redirect(w, r, "/", 301)
			return
		}
	}

	w.Write(splashhtml)
}

func handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	var esettings Settings

        if _, err := os.Stat("./settings.conf"); err == nil {
		jsn, err := ioutil.ReadFile("./settings.conf")
		if err != nil {
			fmt.Fprintf(w, "failed," + err.Error())
			return 
		}

		err = json.Unmarshal(jsn, &esettings)
		if err != nil {
			fmt.Fprintf(w, "failed," + err.Error())
			return 
		}

		if esettings.PasswordProtect == true {
			session, _ := store.Get(r, "defiantmail")

			auth, ok := session.Values["auth"].(bool)
			if !ok {
				http.Redirect(w, r, "/", 301)
				return
			}

			if ! auth {
				http.Redirect(w, r, "/", 301)
				return
			}
		}
        } 

	fname := r.FormValue("fname")
	lname := r.FormValue("lname")
	emailaddr := r.FormValue("emailaddr")
	sendinbluekey := r.FormValue("sendinbluekey")
	awsaccesskey := r.FormValue("awsaccesskey")
	awssecretkey := r.FormValue("awssecretkey")
	s3bucket := r.FormValue("s3bucket")
        passwordprotect := r.FormValue("passwordprotect") 
        username := r.FormValue("username") 
        password := r.FormValue("password") 

	if fname == "" {
		fmt.Fprintf(w, "failed,Missing First Name")
		return
	}

	if lname == "" {
		fmt.Fprintf(w, "failed,Missing Last Name")
		return
	}

	if emailaddr == "" {
		fmt.Fprintf(w, "failed,Missing Your Email Address")
		return
	}

	if sendinbluekey == "" {
		fmt.Fprintf(w, "failed,Missing SendInBlue Key")
		return
	}

	if awsaccesskey == "" {
		fmt.Fprintf(w, "failed,Missing AWS Access Key")
		return
	}

	if awssecretkey == "" {
		fmt.Fprintf(w, "failed,Missing AWS Secret Key")
		return
	}

	if s3bucket == "" {
		fmt.Fprintf(w, "failed,Missing S3 Bucket Name")
		return
	}

	if passwordprotect == "" {
		fmt.Fprintf(w, "failed,Missing Password Protect")
		return
	}

	pprotect, err := strconv.ParseBool(passwordprotect)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return
	}

	if pprotect {
		if username == "" {
			fmt.Fprintf(w, "failed,Missing Username And Password Protect Enabled")
			return
		}

		if password == "" {
			fmt.Fprintf(w, "failed,Missing Password And Password Protect Enabled")
			return
		}
	}


	settings := Settings{}
	settings.FirstName = fname
	settings.LastName = lname
	settings.EmailAddr = emailaddr
	settings.SendInBlueKey = sendinbluekey
	settings.AWSAccessKey = awsaccesskey
	settings.AWSSecretKey = awssecretkey
	settings.S3Bucket = s3bucket
	settings.PasswordProtect = pprotect
	settings.Username = username
	settings.Password = password

	jsn, err := json.Marshal(settings)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return
	}

	err = ioutil.WriteFile("./settings.conf", jsn, 0655)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return
	}

	fmt.Fprintf(w, "success,saved")
	return
}

func handleGetSettings(w http.ResponseWriter, r *http.Request) {
        if _, err := os.Stat("./settings.conf"); err == nil {
		var settings Settings

		if _, err := os.Stat("./settings.conf"); os.IsNotExist(err) {
			http.Redirect(w, r, "/setup", 301)
			return 
		} 

		jsn, err := ioutil.ReadFile("./settings.conf")
		if err != nil {
			fmt.Fprintf(w, "failed," + err.Error())
			return 
		}

		err = json.Unmarshal(jsn, &settings)
		if err != nil {
			fmt.Fprintf(w, "failed," + err.Error())
			return 
		}

		if settings.PasswordProtect == true {
			session, _ := store.Get(r, "defiantmail")

			auth, ok := session.Values["auth"].(bool)
			if !ok {
				http.Redirect(w, r, "/", 301)
				return
			}

			if ! auth {
				http.Redirect(w, r, "/", 301)
				return
			}
		}
        } else {
		fmt.Fprintf(w, "failed,Missing Config File")
		return
	} 

	jsn, err := ioutil.ReadFile("./settings.conf")
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return 
	}

	w.Write(jsn)
	return
}

func handleAddFolder(w http.ResponseWriter, r *http.Request) {
	folder := r.FormValue("folder")
	var esettings Settings

        if _, err := os.Stat("./settings.conf"); err == nil {
		jsn, err := ioutil.ReadFile("./settings.conf")
		if err != nil {
			fmt.Fprintf(w, "failed," + err.Error())
			return 
		}

		err = json.Unmarshal(jsn, &esettings)
		if err != nil {
			fmt.Fprintf(w, "failed," + err.Error())
			return 
		}

		if esettings.PasswordProtect == true {
			session, _ := store.Get(r, "defiantmail")

			auth, ok := session.Values["auth"].(bool)
			if !ok {
				http.Redirect(w, r, "/", 301)
				return
			}

			if ! auth {
				http.Redirect(w, r, "/", 301)
				return
			}
		}
        } 

        if _, err := os.Stat("./mail/" + esettings.FirstName + "/" + folder); err == nil {
		fmt.Fprintf(w, "failed,Folder Already Exists")
		return
	} else {
		os.MkdirAll("./mail/" + esettings.FirstName + "/" + folder, 0700)
		fmt.Fprintf(w, "success,Folder Created")
		return
	}

	return
}

func handleGetFolders(w http.ResponseWriter, r *http.Request) {
	var dirlist []string
	var esettings Settings

        if _, err := os.Stat("./settings.conf"); err == nil {
		jsn, err := ioutil.ReadFile("./settings.conf")
		if err != nil {
			fmt.Fprintf(w, "failed," + err.Error())
			return 
		}

		err = json.Unmarshal(jsn, &esettings)
		if err != nil {
			fmt.Fprintf(w, "failed," + err.Error())
			return 
		}

		if esettings.PasswordProtect == true {
			session, _ := store.Get(r, "defiantmail")

			auth, ok := session.Values["auth"].(bool)
			if !ok {
				http.Redirect(w, r, "/", 301)
				return
			}

			if ! auth {
				http.Redirect(w, r, "/", 301)
				return
			}
		}
        } 

	files, err := filepath.Glob("./mail/" + esettings.FirstName + "/*")
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return
	}

	if len(files) == 0 {
		fmt.Fprintf(w, "failed,no folders")
		return 
	}

	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		if info.IsDir() {
			parts := strings.Split(file, "/")
			dir := parts[len(parts) - 1]
			dirlist = append(dirlist, dir)
		}
	}

	if len(dirlist) == 0 {
		fmt.Fprintf(w, "failed,no folders")
		return
	}

	jsn, err := json.Marshal(dirlist)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return
	}

	w.Write(jsn)
}

func handleRemoveFolder(w http.ResponseWriter, r *http.Request) {
	folder := r.FormValue("folder")
	var esettings Settings

        if _, err := os.Stat("./settings.conf"); err == nil {
		jsn, err := ioutil.ReadFile("./settings.conf")
		if err != nil {
			fmt.Fprintf(w, "failed," + err.Error())
			return 
		}

		err = json.Unmarshal(jsn, &esettings)
		if err != nil {
			fmt.Fprintf(w, "failed," + err.Error())
			return 
		}

		if esettings.PasswordProtect == true {
			session, _ := store.Get(r, "defiantmail")

			auth, ok := session.Values["auth"].(bool)
			if !ok {
				http.Redirect(w, r, "/", 301)
				return
			}

			if ! auth {
				http.Redirect(w, r, "/", 301)
				return
			}
		}
        } 

        if _, err := os.Stat("./mail/" + esettings.FirstName + "/" + folder); err == nil {
		err = os.RemoveAll("./mail/" + esettings.FirstName + "/" + folder)
		if err != nil {
			fmt.Fprintf(w, "failed," + err.Error())
			return
		}

		fmt.Fprintf(w, "success,removed")

		return
	} else {
		fmt.Fprintf(w, "failed,Folder Doesn't Exist")
		return
	}

	return

}

func handleMoveEmail(w http.ResponseWriter, r *http.Request) {
	folder := r.FormValue("moveto")
	file := r.FormValue("file")
	var esettings Settings

        if _, err := os.Stat("./settings.conf"); err == nil {
		jsn, err := ioutil.ReadFile("./settings.conf")
		if err != nil {
			fmt.Fprintf(w, "failed," + err.Error())
			return 
		}

		err = json.Unmarshal(jsn, &esettings)
		if err != nil {
			fmt.Fprintf(w, "failed," + err.Error())
			return 
		}

		if esettings.PasswordProtect == true {
			session, _ := store.Get(r, "defiantmail")

			auth, ok := session.Values["auth"].(bool)
			if !ok {
				http.Redirect(w, r, "/", 301)
				return
			}

			if ! auth {
				http.Redirect(w, r, "/", 301)
				return
			}
		}
        } 

	err := os.Rename("./mail/" + esettings.FirstName + "/" + file, "./mail/" + esettings.FirstName + "/" + folder + "/" + file)
	if err != nil {
		fmt.Fprintf(w, "failed," + err.Error())
		return
	}

	fmt.Fprintf(w, "success,moved")
}

func handleShowLogin(w http.ResponseWriter, r *http.Request) {
	splashhtml, err := ioutil.ReadFile("login.html")
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}

	w.Write(splashhtml)
}

func Authenticate(username string, password string) (bool, error) {
	var settings Settings

        if _, err := os.Stat("./settings.conf"); os.IsNotExist(err) {
		return false, err 
        } 

	jsn, err := ioutil.ReadFile("./settings.conf")
	if err != nil {
		return false, err
	}

	err = json.Unmarshal(jsn, &settings)
	if err != nil {
		return false, err
	}

	if username == settings.Username && password == settings.Password {
		return true, nil
	}

	return false, nil
}

func main() {

        router := mux.NewRouter()
        router.HandleFunc("/whoareyou", handleWhoAreYou)
        router.HandleFunc("/login", handleLogin)
        router.HandleFunc("/logout", handleLogout)
	router.HandleFunc("/showlogin", handleShowLogin)
        router.HandleFunc("/mail", handleMail)
        router.HandleFunc("/getmail", handleGetMail)
	router.HandleFunc("/sendmail", handleSendEmail)
	router.HandleFunc("/savesettings", handleSaveSettings)
	router.HandleFunc("/getsettings", handleGetSettings)
	router.HandleFunc("/setup", handleSetup)
	router.HandleFunc("/deletemail", handleDeleteMail)
	router.HandleFunc("/deleteallmail", handleDeleteAllMail)
	router.HandleFunc("/addfolder", handleAddFolder)
	router.HandleFunc("/removefolder", handleRemoveFolder)
	router.HandleFunc("/getfolders", handleGetFolders)
	router.HandleFunc("/moveemail", handleMoveEmail)
        router.HandleFunc("/", handleSplash)

        err := http.ListenAndServe(":80", router)
        // err := http.ListenAndServeTLS(":443", "cert.pem", "key.pem", router)
        if err != nil {
                fmt.Println(err.Error())
        }
}

