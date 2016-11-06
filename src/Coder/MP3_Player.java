package Coder;

import javafx.application.Application;
import javafx.scene.media.Media;
import javafx.scene.media.MediaPlayer;
import javafx.stage.Stage;
import javafx.util.Duration;

import javax.crypto.KeyGenerator;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;

import static java.lang.Thread.sleep;

public class MP3_Player extends Application {

    String file;
    MediaPlayer player;
    Media pick;
    boolean ready = false;
    Crypto crypto;
    Key k;

    JLabel title;
    JLabel duration;
    JButton play;
    JButton pause;
    JButton jumpback;
    JButton jumpforw;

    int dur;

    @Override
    public void start(Stage primaryStage){
        prepare();
    }

    public static void main(String[] args) {

        launch();
    }

    public MP3_Player(){

        Crypto c = new Crypto("CBC","keyStore.jks","audioKey","pass".toCharArray());
        Key k = c.init();

        File f = new File("player.config");
        if(f.exists()){
            //istnieje, tylko odczyt danych

            //hasło
            char[] pin = null;
            //GET PASSWORD TO KEYSTORE
            JPanel panel = new JPanel();
            JLabel label = new JLabel("Enter password (4 numbers)");
            JPasswordField pass = new JPasswordField(10);
            panel.add(label);
            panel.add(pass);
            String[] options = new String[]{"OK", "Cancel"};
            int option = JOptionPane.showOptionDialog(null, panel, "Password",
                    JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
                    null, options, options[0]);
            if (option == 0 && pass.getPassword().length == 4) // pressing OK button with non-empty passfield
            {
                pin = pass.getPassword();
                //System.out.println("Your password is: " + new String(keypassword));
            } else {
                System.exit(1);
            }

            Key key = null;
            try {
                KeyStore ks = KeyStore.getInstance("JCEKS");
                InputStream readStream = new FileInputStream("keyStore.jks");
                ks.load(readStream, "password".toCharArray());
                key = ks.getKey("config", pin);
                readStream.close();
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
                System.err.println("ERROR READ CONFIG");
                e.printStackTrace();
                System.exit(1);
            }


            try {
                String data = c.decryptConfg("player","config",k);

                String args[] = data.split("#");

                if(args[0].equals("OK")){
                    crypto = new Crypto("CBC","keyStore.jks","audioKey","pass".toCharArray());
                    this.k = crypto.init();
                } else {
                    System.err.println("ERROR DECODE: "+args[0]);
                    System.exit(1);
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(1);
            }
        } else {
            //instalacja

            char[] pin = null;
            //GET PASSWORD TO KEYSTORE
            JPanel panel = new JPanel();
            JLabel label = new JLabel("Set password (4 numbers)");
            JPasswordField pass = new JPasswordField(10);
            panel.add(label);
            panel.add(pass);
            String[] options = new String[]{"OK", "Cancel"};
            int option = JOptionPane.showOptionDialog(null, panel, "Password",
                    JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
                    null, options, options[0]);
            if (option == 0 && pass.getPassword().length == 4) // pressing OK button with non-empty passfield
            {
                pin = pass.getPassword();
                //System.out.println("Your password is: " + new String(keypassword));
            } else {
                System.exit(1);
            }

            Key key1 = null;
            try {
                KeyStore ks = KeyStore.getInstance("JCEKS");
                InputStream readStream = new FileInputStream("keyStore.jks");
                ks.load(readStream, new char[]{'p','a','s','s','w','o','r','d'});

                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
                keyGen.init(256, random);
                key1 = keyGen.generateKey();

                ks.setKeyEntry("config", key1, pin, null);

                OutputStream writeStream = new FileOutputStream("keyStore.jks");
                ks.store(writeStream, "password".toCharArray());
                writeStream.close();
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | NoSuchProviderException e) {
                e.printStackTrace();
            }

            String content = "OK#keyStore.jks#audioKey#pass";
            try {
                OutputStream write = new FileOutputStream("player");
                write.write(content.getBytes("UTF-8"));
                write.close();
                c.encryptString("player","config",k,"");
                Files.deleteIfExists(new File("player").toPath());
                c.decryptConfg("player","config",k);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void prepare() {
        JFrame frame = new JFrame("MP3 Player");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setBounds(200,200,200,500);
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(4,1));

        //loadfile button

        JButton load = new JButton("Load File");
        load.addActionListener(new ActionListener(){
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser chooser = new JFileChooser();
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                        "Encrypted MP3 (*.enc)", "enc");
                chooser.setFileFilter(filter);
                int returnVal = chooser.showOpenDialog(frame);
                if(returnVal == JFileChooser.APPROVE_OPTION) {
                    file = chooser.getSelectedFile().getName();

                    //crypto part
                    try {
                        System.out.println(file);
                        crypto.decrypt(file,k);
                    } catch (IOException e1) {
                        e1.printStackTrace();
                    }
                    if(new File(file.substring(0,file.length()-4)).exists()){
                        new Thread(new Runnable() {
                            @Override
                            public void run() {
                                pick = new Media(Paths.get("new_"+file.substring(0,file.length()-4)).toUri().toString());
                                pick.setOnError(new Runnable() {
                                    @Override
                                    public void run() {
                                        pick.getError().printStackTrace();
                                    }
                                });
                                player = new MediaPlayer(pick);
                                player.setOnError(new Runnable() {
                                    @Override
                                    public void run() {
                                        player.getError().printStackTrace();
                                    }
                                });
                                player.setOnReady(new Runnable(){
                                    @Override
                                    public void run() {
                                        dur = (int)pick.getDuration().toSeconds();
                                        if(pick == null){
                                            System.out.println("pick == NULL");
                                        }
                                        try {
                                            System.out.println(pick.getMetadata().get("title").toString());
                                            title.setText(pick.getMetadata().get("title").toString());
                                        } catch (NullPointerException e1) {
                                            title.setText("--Unknown--");
                                        }
                                    }
                                });
                                player.setOnPlaying(new Runnable(){
                                    @Override
                                    public void run(){
                                        while(player.getStatus().equals(MediaPlayer.Status.PLAYING)){
                                            duration.setText(Integer.toString((int)player.getCurrentTime().toSeconds()) + " : " + Integer.toString(dur));
                                            if((int)player.getCurrentTime().toSeconds() == dur){
                                                player.stop();
                                                player.setStartTime(new Duration(0));
                                                pause.setEnabled(false);
                                                play.setEnabled(true);
                                            }
                                        }
                                    }
                                });


                                while(player.getStatus().equals(MediaPlayer.Status.UNKNOWN)){
                                    try {
                                        sleep(100);
                                    } catch (InterruptedException e1) {
                                        e1.printStackTrace();
                                    }
                                }
                                ready = true;
                                play.setEnabled(true);
                            }
                        }).start();

                    } else {
                        System.err.println("File not found: "+file.substring(0,file.length()-4));
                    }
                }
            }
        });

        //wyswietlacz
        JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayout(2,1));
        title = new JLabel(" ");
        duration = new JLabel(" ");
        panel2.add(title);
        panel2.add(duration);

        //play/pause
        JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayout(1,2));
        play = new JButton("Play");
        play.setEnabled(false);
        play.addActionListener(new ActionListener(){
            @Override
            public void actionPerformed(ActionEvent e) {
                play.setEnabled(false);
                pause.setEnabled(true);
                System.out.println(player.getStatus().toString());
                if(player.getStatus().equals(MediaPlayer.Status.READY) || player.getStatus().equals(MediaPlayer.Status.PAUSED) || player.getStatus().equals(MediaPlayer.Status.PLAYING) || player.getStatus().equals(MediaPlayer.Status.STOPPED)){
                    player.play();
                }
            }
        });
        pause = new JButton("Pause");
        pause.setEnabled(false);
        pause.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                pause.setEnabled(false);
                play.setEnabled(true);
                System.out.println(player.getStatus().toString());
                if(player.getStatus().equals(MediaPlayer.Status.PLAYING)){
                    player.pause();
                }
            }
        });
        panel3.add(play);
        panel3.add(pause);

        JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayout(1,2));
        jumpback = new JButton("<<");
        jumpback.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new Thread(new Runnable(){
                    @Override
                    public void run() {
                        player.pause();
                        player.setStartTime(new Duration(player.getCurrentTime().toMillis() - 3000));
                        player.play();
                    }
                }).start();
            }
        });
        jumpforw = new JButton(">>");
        jumpforw.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                player.pause();
                player.setStartTime(new Duration(player.getCurrentTime().toMillis() + 3000));
                player.play();
            }
        });
        panel4.add(jumpback);
        panel4.add(jumpforw);


        panel.add(load);
        panel.add(panel2);
        panel.add(panel3);
        panel.add(panel4);
        frame.add(panel);

        frame.setVisible(true);
    }

}
