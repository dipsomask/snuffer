package com.dm;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.io.IOException;

/**
 * JavaFX App
 */
public class App extends Application {

    private static Scene scene;
    private ListView<String> listView = new ListView<>();
    private Button startSnifferProcessButton = new Button("Запуск");
    private Button finishSnifferProcessButton = new Button("Завершить");

    @Override
    public void start(Stage stage) throws IOException {
        stage.setTitle("Sniffer");

        startSnifferProcessButton.setOnAction(e -> StartSniffer());
        finishSnifferProcessButton.setOnAction(e -> StopSniffer());
        finishSnifferProcessButton.setDisable(true);

        VBox buttonBox = new VBox(25, startSnifferProcessButton, finishSnifferProcessButton);

        BorderPane layout = new BorderPane();
        layout.setCenter(listView);
        layout.setRight(buttonBox);
        
        Scene scene = new Scene(layout, 400, 300);
        stage.setScene(scene);
        stage.show();

    }

    public void StartSniffer(){
        finishSnifferProcessButton.setDisable(false);
        startSnifferProcessButton.setDisable(true);
        finishSnifferProcessButton.setText("Завершить");
        startSnifferProcessButton.setText("Запуск (не активна)");
        System.out.println("start");
    }

    public void StopSniffer(){
        startSnifferProcessButton.setDisable(false);
        finishSnifferProcessButton.setDisable(true);
        finishSnifferProcessButton.setText("Завершить (не активна)");
        startSnifferProcessButton.setText("Запуск");
        System.out.println("finish");
    }

    public static void main(String[] args) {
        launch();
    }

}