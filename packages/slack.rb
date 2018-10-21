class Slack < U::Package
  script 'dark slack' do
    filepath = '/Applications/Slack.app/Contents/Resources/app.asar.unpacked/src/static/ssb-interop.js'

    js = <<-EOS

document.addEventListener('DOMContentLoaded', function() {
  let tt__customCss = `.menu ul li a:not(.inline_menu_link) {color: #fff !important;}`
  $.ajax({
      url: 'https://cdn.rawgit.com/laCour/slack-night-mode/master/css/raw/black.css',
      success: function(css) {
          $("<style></style>").appendTo('head').html(css + tt__customCss);
          $("<style></style>").appendTo('head').html('#reply_container.upload_in_threads .inline_message_input_container {background: padding-box #545454}');
          $("<style></style>").appendTo('head').html('.p-channel_sidebar {background: #363636 !important}');
          $("<style></style>").appendTo('head').html('#client_body:not(.onboarding):not(.feature_global_nav_layout):before {background: inherit; position: static; }');
      }
  });
});
    EOS

    File.open(filepath, 'a') do |file|
      file.write(js)
    end
  end
end
