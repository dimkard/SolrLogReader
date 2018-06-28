
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import org.json.JSONObject;

public class AuthQueryAspect extends Aspect {  
    
  public static Pattern AUTH= Pattern.compile(
      "^.*?principal:\\s+([^\\]]+).*:q\\=(.*?)(?:&|}).*$", Pattern.DOTALL);

  private List<Query> queryQueue;
    
  private PrintWriter fullOutput;
  private PrintWriter jsonOutput;

  public static class Query {
    String timestamp;
    String username;
    String query;
    public String headLine;
    
    public String toString() {
      return "Timestamp: " + timestamp  + "\nUser: " + username  + "\nQuery: " + query; 
    }
    
    public String toJson() {
     JSONObject obj = new JSONObject();
     obj.put("date_added", timestamp);
     obj.put("user", username);
     obj.put("query", query);
    
     return obj.toString();
    //return "{ \"date_added\":\"" + timestamp  + "\",\"user\":\"" + username  + "\",\"query\":\"" + query +"\"}"; 
    }

  }

  public AuthQueryAspect(String outputDir) {
    prepare(outputDir);
  }

  private void prepare(String outputDir) {
    queryQueue = new ArrayList();
    if (outputDir != null) {
      try {
        fullOutput = new PrintWriter(
                new BufferedWriter(new FileWriter(outputDir + File.separator + "auth-query-report.txt"), 2 ^ 20));
        jsonOutput = new PrintWriter(
                new BufferedWriter(new FileWriter(outputDir + File.separator + "auth-query-report.json"), 2 ^ 20));
        StringBuilder sb = new StringBuilder();
        sb.append("Basic Authentication Query Report" + "\n");
        sb.append("---------------------------------" + "\n\n");
        fullOutput.write(sb.toString());
      } 
      catch (IOException e) {
        throw new RuntimeException(e);
      }
    }
  }
  
  @Override
    public boolean process(String filename, String timestamp, Date dateTs, String headLine, String entry) {
    Matcher m =AUTH.matcher(headLine);
    if (m.matches()) {
      String username = m.group(1);
      String query = m.group(2);
      Query q = new Query();     //"2018-06-11 12:52:12.122" > 2009-01-27T07:02:01Z

    DateTimeFormatter df = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    LocalDateTime dLogTime = LocalDateTime.now();
    dLogTime = LocalDateTime.parse(timestamp, df);
    String sLogTime = dLogTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME) + "Z";
      q.timestamp = sLogTime;
      q.username = username;
      q.query = query;
      q.headLine = headLine;
  
      synchronized (queryQueue) {

        queryQueue.add(q);
        if (fullOutput != null) {
          fullOutput.write(q.toString() + "\n");
          fullOutput.write("Log: " + q.headLine + "\n\n");
        }

        if (jsonOutput != null) {
            if (queryQueue.size() == 1) {
                jsonOutput.write("{\"log\": [");
            }
            else {
                jsonOutput.write(",");
            }
            jsonOutput.write(q.toJson());
        }
      }
      return false;
     
    } 
    return false;
  }

  
  @Override
  public void printReport(PrintStream out) {
    out.println("Basic Authentication Query Report");
    out.println("----------------------------------");
    out.println();

    out.println();
    out.println("Queries:");
    out.println();
    Query q;
    Iterator qiter = queryQueue.iterator();
    
    synchronized (queryQueue) {
      while (qiter.hasNext()) {
        q = (Query) qiter.next();
        out.println(q);
        out.println("Log: " + q.headLine);
        out.println();
      }
    }
  }


  @Override
  public void close() {
    if (fullOutput != null) fullOutput.close();
    if (jsonOutput != null) {
        jsonOutput.write("]}");
        jsonOutput.close();
    }
  }
  
}
