module com.dm {
    requires javafx.controls;
    requires javafx.fxml;

    opens com.dm to javafx.fxml;
    exports com.dm;
}
