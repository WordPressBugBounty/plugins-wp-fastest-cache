<?php
	class PreloadWPFC{
		private static $exclude_rules = false;

		public static function wpml_get_permalink($post_id, $permalink){
			$my_post_language_details = apply_filters( 'wpml_post_language_details', NULL, $post_id) ;

			if(is_array($my_post_language_details) && isset($my_post_language_details["language_code"])){
				$wpml_permalink = apply_filters( 'wpml_permalink', $permalink , $my_post_language_details["language_code"] ); 

				return $wpml_permalink;
			}

			return $permalink;
		}

		public static function set_preload($slug){
			$preload_arr = array();

			if(!empty($_POST) && isset($_POST["wpFastestCachePreload"])){
				if(!current_user_can('manage_options')){
					wp_die("Must be admin");
				}

				if(isset($_POST["wpFastestCachePreload_sitemap"]) && $_POST["wpFastestCachePreload_sitemap"]){
					$sitemap_url = explode(",", $_POST["wpFastestCachePreload_sitemap"]);
					$sitemap_arr = array();

					foreach ($sitemap_url as $s_key => $s_value) {
						$s_value = esc_url($s_value);

						array_push($sitemap_arr, array("url" => $s_value, "pointer" => 0));
					}

					$preload_arr["sitemaps"] = $sitemap_arr;
				}else{
					foreach ($_POST as $key => $value) {
						$key = esc_attr($key);
						$value = esc_attr($value);
						
						preg_match("/wpFastestCachePreload_(.+)/", $key, $type);

						if(!empty($type)){
							if($type[1] == "restart" || $type[1] == "sitemap"){
								//to need to remove "restart" value
							}else if($type[1] == "number"){
								$preload_arr[$type[1]] = $value; 
							}else{
								$preload_arr[$type[1]] = 0; 
							}
						}
					}
				}
			}

			if($data = get_option("WpFastestCachePreLoad")){
				$preload_std = json_decode($data);

				if(empty($preload_arr)){
					// clear cache process

					if(isset($preload_std->sitemaps) && !empty($preload_std->sitemaps)){
						foreach ($preload_std->sitemaps as $s_key => $s_value) {
							$s_value->pointer = 0;
						}
					}else{
						foreach ($preload_std as $key => &$value) {
							if($key != "number"){
								$value = 0;
							}
						}
					}

				}else{
					// save settings process

					if(isset($preload_arr["sitemaps"])){
						if(isset($preload_std->sitemaps) && !empty($preload_std->sitemaps)){
							for ($i=0; $i < count($preload_arr["sitemaps"]) ; $i++) {
								for ($j=0; $j < count($preload_std->sitemaps); $j++) {
									if($preload_arr["sitemaps"][$i]["url"] == $preload_std->sitemaps[$j]->url){

										if(isset($preload_std->sitemaps[$j]->pointer)){
											$preload_arr["sitemaps"][$i]["pointer"] = $preload_std->sitemaps[$j]->pointer;
										}

										if(isset($preload_std->sitemaps[$j]->total)){
											$preload_arr["sitemaps"][$i]["total"] = $preload_std->sitemaps[$j]->total;
										}
									}
								}
							}

							$preload_std = $preload_arr;
						}else{
							foreach ($preload_arr as $key => &$value) {
								if(!empty($preload_std->$key)){
									if($key != "number"){
										$value = $preload_std->$key;
									}
								}
							}

							$preload_std = $preload_arr;
						}
					}else{
						foreach ($preload_arr as $key => &$value) {
							if(!empty($preload_std->$key)){
								if($key != "number"){
									$value = $preload_std->$key;
								}
							}
						}

						$preload_std = $preload_arr;
					}

				}


				update_option("WpFastestCachePreLoad", json_encode($preload_std));

				if(!wp_next_scheduled($slug."_Preload")){
					wp_schedule_event(time() + 5, 'everyfiveminute', $slug."_Preload");
				}
			}else{
				if(!empty($preload_arr)){
					add_option("WpFastestCachePreLoad", json_encode($preload_arr), null, "yes");

					if(!wp_next_scheduled($slug."_Preload")){
						wp_schedule_event(time() + 5, 'everyfiveminute', $slug."_Preload");
					}
				}else{
					//toDO
				}
			}
			

		}

		public static function statistic($pre_load = false){
			$total = new stdClass();


			if(isset($pre_load->homepage)){
				$total->homepage = 1;
			}

			if(isset($pre_load->customposttypes)){
				global $wpdb;
				$post_types = get_post_types(array('public' => true), "names", "and"); 
				$where_query = "";

				foreach ($post_types as $post_type_key => $post_type_value) {
					if(!in_array($post_type_key, array("post", "page", "attachment"))){
						$where_query = $where_query.$wpdb->prefix."posts.post_type = '".$post_type_value."' OR ";
					}

				}

				if($where_query){
					$where_query = preg_replace("/(\s*OR\s*)$/", "", $where_query);
		    		
		    		$recent_custom_posts = $wpdb->get_results("SELECT SQL_CALC_FOUND_ROWS  COUNT(".$wpdb->prefix."posts.ID) as total FROM ".$wpdb->prefix."posts  WHERE 1=1  AND (".$where_query.") AND ((".$wpdb->prefix."posts.post_status = 'publish'))  ORDER BY ".$wpdb->prefix."posts.ID", ARRAY_A);
		    		$total->customposttypes = $recent_custom_posts[0]["total"];
		    	}
			}

			if(isset($pre_load->post)){
				$count_posts = wp_count_posts("post", array('post_status' => 'publish', 'suppress_filters' => true));

				$total->post = $count_posts->publish;
			}

			if(isset($pre_load->attachment)){
				$total_attachments = wp_count_attachments();

				$total->attachment = array_sum((array)$total_attachments) - $total_attachments->trash;
			}




			if(isset($pre_load->page)){
				$count_pages = wp_count_posts("page", array('post_status' => 'publish', 'suppress_filters' => true));

				$total->page = $count_pages->publish;
			}

			if(isset($pre_load->category)){
				$total->category = wp_count_terms("category", array('hide_empty' => false));
			}

			if(isset($pre_load->tag)){
				$total->tag = wp_count_terms("post_tag", array('hide_empty' => false));
			}

			if(isset($pre_load->customTaxonomies)){
				$taxo = get_taxonomies(array('public' => true, '_builtin' => false), "names", "and");

				if(count($taxo) > 0){
					$total->customTaxonomies = wp_count_terms($taxo, array('hide_empty' => false));
				}
			}


			foreach ($total as $key => $value) {
				$pre_load->$key = $pre_load->$key == -1 ? $value : $pre_load->$key;
				echo esc_html($key).": ".esc_html($pre_load->$key)."/".esc_html($value)."<br>";
			}
		}

		public static function create_preload_cache_default($pre_load, $options){

			if(defined("WPFC_PRELOAD_NUMBER") && WPFC_PRELOAD_NUMBER){
				$number = WPFC_PRELOAD_NUMBER;
			}else{
				$number = $pre_load->number;
			}

			//START:ORDER
			if(isset($pre_load->order) && $pre_load->order){
				$order_arr = explode(",", $pre_load->order);
			}else{
				if(isset($options->wpFastestCachePreload_order) && $options->wpFastestCachePreload_order){
					$order_arr = explode(",", $options->wpFastestCachePreload_order);
				}
			}

			if(isset($order_arr) && is_array($order_arr)){
				foreach ($order_arr as $o_key => $o_value){
					if($o_value == "order" || $o_value == "number"){
						unset($order_arr[$o_key]);
					}

					if(!isset($pre_load->$o_value)){
						unset($order_arr[$o_key]);
					}

				}
				$order_arr = array_values($order_arr);
			}
			
			$current_order = isset($order_arr[0]) ? $order_arr[0] : "go";
			//START:END



			$urls_limit = isset($options->wpFastestCachePreload_number) ? $options->wpFastestCachePreload_number : 4; // must be even
			$urls = array();

			if(isset($options->wpFastestCacheMobileTheme) && $options->wpFastestCacheMobileTheme){
				$mobile_theme = true;
				$number = round($number/2);
			}else{
				$mobile_theme = false;
			}



			// HOME
			if(isset($current_order) && ($current_order == "homepage" || $current_order == "go")){
				if(isset($pre_load->homepage) && $pre_load->homepage > -1){
					if($mobile_theme){
						array_push($urls, array("url" => get_option("home"), "user-agent" => "mobile"));
						$number--;
					}

					array_push($urls, array("url" => get_option("home"), "user-agent" => "desktop"));
					$number--;
					
					$pre_load->homepage = -1;
				}
				
			}


			// CUSTOM POSTS
			if(isset($current_order) && ($current_order == "customposttypes" || $current_order == "go")){
				if($number > 0 && isset($pre_load->customposttypes) && $pre_load->customposttypes > -1){
		    		global $wpdb;
					$post_types = get_post_types(array('public' => true), "names", "and"); 
					$where_query = "";

					foreach ($post_types as $post_type_key => $post_type_value) {
						if(!in_array($post_type_key, array("post", "page", "attachment"))){
							$where_query = $where_query.$wpdb->prefix."posts.post_type = '".$post_type_value."' OR ";
						}

					}

					if($where_query){
						$where_query = preg_replace("/(\s*OR\s*)$/", "", $where_query);
			    		
			    		$recent_custom_posts = $wpdb->get_results("SELECT SQL_CALC_FOUND_ROWS  ".$wpdb->prefix."posts.ID FROM ".$wpdb->prefix."posts  WHERE 1=1  AND (".$where_query.") AND ((".$wpdb->prefix."posts.post_status = 'publish'))  ORDER BY ".$wpdb->prefix."posts.ID DESC LIMIT ".$pre_load->customposttypes.", ".$number, ARRAY_A);

			    		if(count($recent_custom_posts) > 0){
			    			foreach ($recent_custom_posts as $key => $post) {
			    				if($mobile_theme){
			    					array_push($urls, array("url" => self::wpml_get_permalink($post["ID"], get_permalink($post["ID"])), "user-agent" => "mobile"));
			    					$number--;
			    				}

		    					array_push($urls, array("url" => self::wpml_get_permalink($post["ID"], get_permalink($post["ID"])), "user-agent" => "desktop"));
		    					$number--;

			    				$pre_load->customposttypes = $pre_load->customposttypes + 1;
			    			}
			    		}else{
			    			$pre_load->customposttypes = -1;
			    		}
					}
				}
			}


			// POST
			if(isset($current_order) && ($current_order == "post" || $current_order == "go")){
				if($number > 0 && isset($pre_load->post) && $pre_load->post > -1){
		    		// $recent_posts = wp_get_recent_posts(array(
								// 			'numberposts' => $number,
								// 		    'offset' => $pre_load->post,
								// 		    'orderby' => 'ID',
								// 		    'order' => 'DESC',
								// 		    'post_type' => 'post',
								// 		    'post_status' => 'publish',
								// 		    'suppress_filters' => true
								// 		    ), ARRAY_A);
		    		global $wpdb;
		    		$recent_posts = $wpdb->get_results("SELECT SQL_CALC_FOUND_ROWS  ".$wpdb->prefix."posts.ID FROM ".$wpdb->prefix."posts  WHERE 1=1  AND (".$wpdb->prefix."posts.post_type = 'post') AND ((".$wpdb->prefix."posts.post_status = 'publish'))  ORDER BY ".$wpdb->prefix."posts.ID DESC LIMIT ".$pre_load->post.", ".$number, ARRAY_A);


		    		if(count($recent_posts) > 0){
		    			foreach ($recent_posts as $key => $post) {
		    				if($mobile_theme){
		    					array_push($urls, array("url" => self::wpml_get_permalink($post["ID"], get_permalink($post["ID"])), "user-agent" => "mobile"));
		    					$number--;
		    				}

	    					array_push($urls, array("url" => self::wpml_get_permalink($post["ID"], get_permalink($post["ID"])), "user-agent" => "desktop"));
	    					$number--;

		    				$pre_load->post = $pre_load->post + 1;
		    			}
		    		}else{
		    			$pre_load->post = -1;
		    		}
				}
			}



			// ATTACHMENT
			if(isset($current_order) && ($current_order == "attachment" || $current_order == "go")){
				if($number > 0 && isset($pre_load->attachment) && $pre_load->attachment > -1){
					global $wpdb;
		    		$recent_attachments = $wpdb->get_results("SELECT SQL_CALC_FOUND_ROWS  ".$wpdb->prefix."posts.ID FROM ".$wpdb->prefix."posts  WHERE 1=1  AND (".$wpdb->prefix."posts.post_type = 'attachment') ORDER BY ".$wpdb->prefix."posts.ID DESC LIMIT ".$pre_load->attachment.", ".$number, ARRAY_A);

		    		if(count($recent_attachments) > 0){
		    			foreach ($recent_attachments as $key => $attachment) {
		    				if($mobile_theme){
		    					array_push($urls, array("url" => get_permalink($attachment["ID"]), "user-agent" => "mobile"));
		    					$number--;
		    				}

	    					array_push($urls, array("url" => get_permalink($attachment["ID"]), "user-agent" => "desktop"));
	    					$number--;

		    				$pre_load->attachment = $pre_load->attachment + 1;
		    			}
		    		}else{
		    			$pre_load->attachment = -1;
		    		}
				}
			}

			// PAGE
			if(isset($current_order) && ($current_order == "page" || $current_order == "go")){
				if($number > 0 && isset($pre_load->page) && $pre_load->page > -1){

					global $wpdb;
		    		$pages = $wpdb->get_results("SELECT SQL_CALC_FOUND_ROWS  ".$wpdb->prefix."posts.ID FROM ".$wpdb->prefix."posts  WHERE 1=1  AND (".$wpdb->prefix."posts.post_type = 'page') AND ((".$wpdb->prefix."posts.post_status = 'publish'))  ORDER BY ".$wpdb->prefix."posts.ID DESC LIMIT ".$pre_load->page.", ".$number, ARRAY_A);


					if(count($pages) > 0){
						foreach ($pages as $key => $page) {
		    				if($mobile_theme){
		    					array_push($urls, array("url" => get_page_link($page["ID"]), "user-agent" => "mobile"));
		    					$number--;
		    				}

	    					array_push($urls, array("url" => get_page_link($page["ID"]), "user-agent" => "desktop"));
	    					$number--;

		    				$pre_load->page = $pre_load->page + 1;
						}
					}else{
						$pre_load->page = -1;
					}
				}
			}

			// CATEGORY
			if(isset($current_order) && ($current_order == "category" || $current_order == "go")){
				if($number > 0 && isset($pre_load->category) && $pre_load->category > -1){
					$categories = get_terms(array(
												'taxonomy'          => array('category'),
											    'orderby'           => 'id', 
											    'order'             => 'ASC',
											    'hide_empty'        => false, 
											    'number'            => $number, 
											    'fields'            => 'all', 
											    'pad_counts'        => false, 
											    'offset'            => $pre_load->category
											));

					if(count($categories) > 0){
						foreach ($categories as $key => $category) {
							$term_link = get_term_link($category->slug, $category->taxonomy);

							if(isset($term_link->errors)){
								continue;
							}

							if($mobile_theme){
								array_push($urls, array("url" => $term_link, "user-agent" => "mobile"));
								$number--;
							}

							array_push($urls, array("url" => $term_link, "user-agent" => "desktop"));
							$number--;

							$pre_load->category = $pre_load->category + 1;
						}

					}else{
						$pre_load->category = -1;
					}
				}
			}

			// TAG
			if(isset($current_order) && ($current_order == "tag" || $current_order == "go")){
				if($number > 0 && isset($pre_load->tag) && $pre_load->tag > -1){
					$tags = get_terms(array(
												'taxonomy'          => array('post_tag'),
											    'orderby'           => 'id', 
											    'order'             => 'ASC',
											    'hide_empty'        => false, 
											    'number'            => $number, 
											    'fields'            => 'all', 
											    'pad_counts'        => false, 
											    'offset'            => $pre_load->tag
											));

					if(count($tags) > 0){
						foreach ($tags as $key => $tag) {
							if($mobile_theme){
								array_push($urls, array("url" => get_term_link($tag->slug, $tag->taxonomy), "user-agent" => "mobile"));
								$number--;
							}

							array_push($urls, array("url" => get_term_link($tag->slug, $tag->taxonomy), "user-agent" => "desktop"));
							$number--;

							$pre_load->tag = $pre_load->tag + 1;

						}
					}else{
						$pre_load->tag = -1;
					}
				}
			}

			// Custom Taxonomies
			if(isset($current_order) && ($current_order == "customTaxonomies" || $current_order == "go")){
				if($number > 0 && isset($pre_load->customTaxonomies) && $pre_load->customTaxonomies > -1){
					$taxo = get_taxonomies(array('public'   => true, '_builtin' => false), "names", "and");

					if(count($taxo) > 0){
						$custom_taxos = get_terms(array(
								'taxonomy'          => array_values($taxo),
							    'orderby'           => 'id', 
							    'order'             => 'ASC',
							    'hide_empty'        => false, 
							    'number'            => $number, 
							    'fields'            => 'all', 
							    'pad_counts'        => false, 
							    'offset'            => $pre_load->customTaxonomies
							));

						if(count($custom_taxos) > 0){
							foreach ($custom_taxos as $key => $custom_tax) {
								if($mobile_theme){
									array_push($urls, array("url" => get_term_link($custom_tax->slug, $custom_tax->taxonomy), "user-agent" => "mobile"));
									$number--;
								}

								array_push($urls, array("url" => get_term_link($custom_tax->slug, $custom_tax->taxonomy), "user-agent" => "desktop"));
								$number--;

								$pre_load->customTaxonomies = $pre_load->customTaxonomies + 1;

							}
						}else{
							$pre_load->customTaxonomies = -1;
						}
					}else{
						$pre_load->customTaxonomies = -1;
					}
				}
			}


			if(isset($pre_load->$current_order) && $pre_load->$current_order == -1){
				array_shift($order_arr);

				if(isset($order_arr[0])){
					$pre_load->order = implode(",", $order_arr);
					
					update_option("WpFastestCachePreLoad", json_encode($pre_load));

					self::create_preload_cache($options);
				}else{
					unset($pre_load->order);
				}
			}

			if(count($urls) > 0){
				foreach ($urls as $key => $arr) {
					$user_agent = "";

					if($arr["user-agent"] == "desktop"){
						$user_agent = "WP Fastest Cache Preload Bot";
					}else if($arr["user-agent"] == "mobile"){
						$user_agent = "WP Fastest Cache Preload iPhone Mobile Bot";
					}


					if(self::is_excluded($arr["url"])){
						$status = "<strong style=\"color:blue;\">Excluded</strong>";
					}else{
						if($GLOBALS["wp_fastest_cache"]->wpfc_remote_get($arr["url"], $user_agent)){
							$status = "<strong style=\"color:lightgreen;\">OK</strong>";
						}else{
							$status = "<strong style=\"color:red;\">ERROR</strong>";
						}
					}




					echo $status." ".esc_html($arr["url"])." (".esc_html($arr["user-agent"]).")<br>";
				}
				echo "<br>";
				echo count($urls)." page have been cached";

	    		update_option("WpFastestCachePreLoad", json_encode($pre_load));

	    		echo "<br><br>";

	    		self::statistic($pre_load);

			}else{
				if(isset($options->wpFastestCachePreload_restart)){
					foreach ($pre_load as $pre_load_key => &$pre_load_value) {
						//if($pre_load_key != "number" && $pre_load_key != "order"){
						if($pre_load_key != "number"){
							$pre_load_value = 0;
						}
					}

					update_option("WpFastestCachePreLoad", json_encode($pre_load));

					echo "Preload Restarted";

					if($varnish_datas = get_option("WpFastestCacheVarnish")){
						include_once('varnish.php');
						VarnishWPFC::purge_cache($varnish_datas);
					}

					include_once('cdn.php');
					CdnWPFC::cloudflare_clear_cache();
				}else{
					echo "Completed";
					
					wp_clear_scheduled_hook("wp_fastest_cache_Preload");
				}
			}
		}

		public static function prepare_sitemap($url, $sitemap_cache_path){
			if(!empty($url)){
				$content = $GLOBALS["wp_fastest_cache"]->wpfc_remote_get($url, "xxxx", true);

				$content = strtolower($content);

				$content = preg_replace("/<\?\s*xml[^\>]*>/i", "", $content);
				
				// to remove comments
				$content = preg_replace("/\<\!\-\-((?:(?!-->).)+)\-\-\>/", "", $content);

				$content = preg_replace("/<((?:(?!url|loc).)+)>((?:(?!http).)+)<((?:(?!url|loc).)+)>/i", "", $content);
				
				// to remove <image:image></image:image> tag
				$content = preg_replace("/<\s*image\s*:\s*image\s*>((?:(?!\<\s*\/\s*image\s*:\s*image\s*>).)+)<\s*\/\s*image\s*\:\s*image\s*>/s", "", $content);
				
				if(preg_match("/<\s*sitemapindex[^\>]+>/", $content)){
					$content = preg_replace("/<\/?sitemapindex[^\>]*>/i", "", $content);
					
					$content = preg_replace("/\s/i", "", $content);
					$content = preg_replace("/<\/sitemap>/i", "</sitemap>\n", $content);

				}else{
					$content = preg_replace("/<\/?urlset[^\>]*>/i", "", $content);


					$content = preg_replace("/\s/i", "", $content);
					$content = preg_replace("/<\/url>/i", "</url>\n", $content);

				}

				if(!is_dir($GLOBALS["wp_fastest_cache"]->getWpContentDir("/cache/all/"))){
					@mkdir($GLOBALS["wp_fastest_cache"]->getWpContentDir("/cache/all/"), 0755, true);
				}

				if(!is_dir($GLOBALS["wp_fastest_cache"]->getWpContentDir("/cache/all/preload-sitemap"))){
					@mkdir($GLOBALS["wp_fastest_cache"]->getWpContentDir("/cache/all/preload-sitemap"), 0755, true);
				}

				file_put_contents($sitemap_cache_path, $content);

				return $content;
			}

			return false;
		}

		public static function extract_sitemap_index($content, $sitemaps){
			if($content){
				preg_match_all("/<sitemap><loc>([^\>\<]+)<\/loc><\/sitemap>/", $content, $out);

				if(isset($out[1]) && isset($out[1][0])){
					foreach ($out[1] as $key => $value) {
						$sm_obj = (object) array("url" => $value, "pointer" => 0, "total" => 0);

						if(!in_array($value, array_column($sitemaps, 'url'))){
							array_push($sitemaps, $sm_obj);
						}
					}
				}
			}

			return $sitemaps;
		}

		public static function create_preload_cache_sitemap($pre_load, $options){
			if(!isset($pre_load->sitemaps[0])){
				die("No sitemap detected!");
			}

			if(defined("WPFC_PRELOAD_NUMBER") && WPFC_PRELOAD_NUMBER){
				$number = WPFC_PRELOAD_NUMBER;
			}else{
				$number = $options->wpFastestCachePreload_number;
			}

			$urls = array();

			if(isset($options->wpFastestCacheMobileTheme) && $options->wpFastestCacheMobileTheme){
				$mobile_theme = true;
				$number = round($number/2);
			}else{
				$mobile_theme = false;
			}


			foreach ($pre_load->sitemaps as $s_key => &$s_value) {
				$sitemap_cache_path = $GLOBALS["wp_fastest_cache"]->getWpContentDir("/cache/all/preload-sitemap/".base64_encode($s_value->url).".xml");

				if(!file_exists($sitemap_cache_path) || !isset($s_value->total)){
					$content = self::prepare_sitemap($s_value->url, $sitemap_cache_path);

					$s_value->total = substr_count($content, '<url>');

					if($s_value->total == 0){
						$pre_load->sitemaps = self::extract_sitemap_index($content, $pre_load->sitemaps);
						unset($pre_load->sitemaps[$s_key]);

						$pre_load->sitemaps = array_values($pre_load->sitemaps);

						update_option("WpFastestCachePreLoad", json_encode($pre_load));

						die($s_value->url." was extracted");
					}
				}

				$s_value->pointer = $s_value->pointer > 0 ? $s_value->pointer : 1;
				
				if($s_value->pointer < $s_value->total){

					$file = fopen($sitemap_cache_path, "r");

					for ($i = 1; $i < $s_value->pointer; $i++) {
					    fgets($file);
					}

					for ($j=0; $j < $number; $j++) {

						$specific_line = fgets($file);

						$specific_line = strip_tags($specific_line);
						$specific_line = trim($specific_line);

						if($specific_line){
							if($mobile_theme){
								array_push($urls, array("url" => $specific_line, "user-agent" => "mobile"));
							}

			    			array_push($urls, array("url" => $specific_line, "user-agent" => "desktop"));
						}

					}

					fclose($file);

					$s_value->pointer = $s_value->pointer + $number;
					$s_value->pointer = $s_value->pointer > $s_value->total ? $s_value->total : $s_value->pointer;

					break;
				}

			}

			if(count($urls) > 0){
				foreach ($urls as $key => $arr) {
					$user_agent = "";

					if($arr["user-agent"] == "desktop"){
						$user_agent = "WP Fastest Cache Preload Bot";
					}else if($arr["user-agent"] == "mobile"){
						$user_agent = "WP Fastest Cache Preload iPhone Mobile Bot";
					}


					if(self::is_excluded($arr["url"])){
						$status = "<strong style=\"color:blue;\">Excluded</strong>";
					}else{
						if($GLOBALS["wp_fastest_cache"]->wpfc_remote_get($arr["url"], $user_agent)){
							$status = "<strong style=\"color:lightgreen;\">OK</strong>";
						}else{
							$status = "<strong style=\"color:red;\">ERROR</strong>";
						}
					}




					echo $status." ".esc_html($arr["url"])." (".esc_html($arr["user-agent"]).")<br>";
				}


				echo "\n\n<br><br>";


				foreach ($pre_load->sitemaps as $sres_key => $sres_value) {

					if(isset($sres_value->total)){
						$cached_page_number = $sres_value->pointer;
						
						if($sres_value->pointer == $sres_value->total){
							$cached_page_number = $sres_value->pointer;
						}else{
							$cached_page_number--;

							$cached_page_number = max($cached_page_number, 0);
						}

						echo esc_html($sres_value->url).": ".esc_html($cached_page_number)."/".esc_html($sres_value->total)."<br>\n";
					}else{
						echo esc_html($sres_value->url).": -<br>\n";
					}
				}

				update_option("WpFastestCachePreLoad", json_encode($pre_load));

			}else{
				if(isset($options->wpFastestCachePreload_restart)){

					foreach ($pre_load->sitemaps as $r_key => &$r_value) {
						$r_value->pointer = 0;
					}

					update_option("WpFastestCachePreLoad", json_encode($pre_load));

					echo "Preload Restarted";

					// clearing the sitemap cache in order to get the latest sitemap updates
					$GLOBALS["wp_fastest_cache"]->rm_folder_recursively($GLOBALS["wp_fastest_cache"]->getWpContentDir("/cache/all/preload-sitemap"));

					if($varnish_datas = get_option("WpFastestCacheVarnish")){
						include_once('varnish.php');
						VarnishWPFC::purge_cache($varnish_datas);
					}

					include_once('cdn.php');
					CdnWPFC::cloudflare_clear_cache();
				}else{
					echo "Completed";
					
					wp_clear_scheduled_hook("wp_fastest_cache_Preload");
				}
			}





		}

		public static function create_preload_cache($options){

			if(!isset($options->wpFastestCacheStatus)){
				die("Cache System must be enabled");
			}

			if($data = get_option("WpFastestCachePreLoad")){

				$pre_load = json_decode($data);

				if(isset($pre_load->sitemaps)){
					self::create_preload_cache_sitemap($pre_load, $options);
				}else{
					self::create_preload_cache_default($pre_load, $options);
				}
				

			}

			if(isset($_GET) && isset($_GET["type"])  && $_GET["type"] == "preload"){
				die();
			}
		}

		public static function is_excluded($url){
			if(!is_string($url)){
				return false;
			}

			$request_url = parse_url($url, PHP_URL_PATH);
			
			if($request_url){
				$request_url = urldecode(trim($request_url, "/"));
			}

			if(!$request_url){
				return false;
			}


			if(self::$exclude_rules === false){
				if($json_data = get_option("WpFastestCacheExclude")){
					self::$exclude_rules = json_decode($json_data);
				}else{
					self::$exclude_rules = array();
				}
			}

			foreach((array)self::$exclude_rules as $key => $value){
				if($value->prefix == "exact"){
					if(strtolower($value->content) == strtolower($request_url)){
						return true;	
					}
				}else{
					if($value->prefix == "startwith"){
						$preg_match_rule = "^".preg_quote($value->content, "/");
					}else if($value->prefix == "contain"){
						$preg_match_rule = preg_quote($value->content, "/");
					}
					
					if(isset($preg_match_rule)){
						if(preg_match("/".$preg_match_rule."/i", $request_url)){
							return true;
						}
					}
				}
			}

			return false;
		}
	}
?>