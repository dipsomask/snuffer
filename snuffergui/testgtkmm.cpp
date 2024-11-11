#include <gtkmm.h>

using namespace std;

class MyWindow : public Gtk::Window {
public:
    MyWindow() {
        set_title("Hello gtkmm");
        set_default_size(200, 200);
        show_all_children();
    }
};

int main(int argc, char *argv[]) {
    auto app = Gtk::Application::create(argc, argv, "org.gtkmm.example");
    MyWindow window;
    return app->run(window);
}

