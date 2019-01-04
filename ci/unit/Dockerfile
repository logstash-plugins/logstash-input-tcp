ARG ELASTIC_STACK_VERSION
FROM docker.elastic.co/logstash/logstash:$ELASTIC_STACK_VERSION
COPY --chown=logstash:logstash Gemfile /usr/share/plugins/logstash-input-tcp/Gemfile
COPY --chown=logstash:logstash *.gemspec /usr/share/plugins/logstash-input-tcp/
COPY --chown=logstash:logstash version /usr/share/plugins/logstash-input-tcp/
RUN cp /usr/share/logstash/logstash-core/versions-gem-copy.yml /usr/share/logstash/versions.yml
ENV PATH="${PATH}:/usr/share/logstash/vendor/jruby/bin"
ENV LOGSTASH_SOURCE=1
ENV JARS_SKIP="true"
RUN gem install bundler -v '< 2'
WORKDIR /usr/share/plugins/logstash-input-tcp
RUN bundle install
COPY --chown=logstash:logstash . /usr/share/plugins/logstash-input-tcp
RUN bundle exec rake vendor
